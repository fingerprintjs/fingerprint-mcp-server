package fpmcpserver

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// skillFrontmatter holds the YAML frontmatter parsed from a SKILL.md file.
type skillFrontmatter struct {
	Name        string
	Description string
}

// parseSkillPrompt extracts the YAML frontmatter and the full file content.
func parseSkillPrompt(data []byte) (*skillFrontmatter, string, error) {
	content := string(data)
	fm, err := parseFrontmatter(data)
	if err != nil {
		return nil, "", fmt.Errorf("parsing frontmatter: %w", err)
	}

	return fm, content, nil
}

// parseFrontmatter extracts name and description from YAML frontmatter
// delimited by "---" lines.
func parseFrontmatter(data []byte) (*skillFrontmatter, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	// First line must be "---"
	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "---" {
		return nil, errors.New("missing opening frontmatter delimiter")
	}

	fm := &skillFrontmatter{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "---" {
			// End of frontmatter
			if fm.Name == "" {
				return nil, errors.New("frontmatter missing required 'name' field")
			}
			return fm, nil
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "name":
			fm.Name = strings.TrimSpace(value)
		case "description":
			fm.Description = strings.TrimSpace(value)
		}
	}

	return nil, errors.New("missing closing frontmatter delimiter")
}

func stripFrontmatter(data string) string {
	rest, ok := strings.CutPrefix(data, "---\n")
	if !ok {
		return data
	}
	if _, body, found := strings.Cut(rest, "\n---\n"); found {
		return strings.TrimLeft(body, "\n")
	}

	return data
}

const defaultGetStartedURL = "https://raw.githubusercontent.com/fingerprintjs/skills/main/skills/fingerprint-get-started/SKILL.md"

const getStartedPlaceholder = "{{get_started}}"

const (
	getStartedTTL        = time.Hour
	getStartedRetryAfter = time.Minute
	getStartedTimeout    = 5 * time.Second
	getStartedMaxBytes   = 256 << 10
)

const getStartedFallback = "Fetch and follow %s, then apply it to this project. It detects the stack and walks the Get Started checklist."

type remoteSkill struct {
	url    string
	client *http.Client
	ttl    time.Duration
	// Set when the content is spliced into a prompt, not when served as a file.
	strip bool

	mu        sync.Mutex
	content   string
	fetchedAt time.Time
	nextRetry time.Time
}

func (r *remoteSkill) get(ctx context.Context, logger *slog.Logger) (string, bool) {
	if r == nil || r.url == "" {
		return "", false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.content != "" && time.Since(r.fetchedAt) < r.ttl {
		return r.content, true
	}

	// Without this an outage costs every prompts/get a full timeout, serialized
	// on the mutex.
	if time.Now().Before(r.nextRetry) {
		return r.content, r.content != ""
	}

	content, err := r.fetch(ctx)
	if err != nil {
		r.nextRetry = time.Now().Add(getStartedRetryAfter)
		if r.content != "" {
			logger.Warn("refetching Get Started skill failed, serving cached copy", "url", r.url, "err", err)
			return r.content, true
		}
		logger.Warn("fetching Get Started skill failed, falling back to pointer", "url", r.url, "err", err)
		return "", false
	}

	r.content = content
	r.fetchedAt = time.Now()
	r.nextRetry = time.Time{}

	return content, true
}

func (r *remoteSkill) fetch(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, getStartedTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	client := r.client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, getStartedMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}
	if len(body) > getStartedMaxBytes {
		return "", fmt.Errorf("document larger than %d bytes", getStartedMaxBytes)
	}

	content := string(body)
	if r.strip {
		content = stripFrontmatter(content)
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return "", errors.New("empty document")
	}

	return content, nil
}

func (a *App) getStartedSection(ctx context.Context) string {
	url := a.opts.getStartedURL()
	if skill, ok := a.getStarted.get(ctx, a.opts.logger()); ok {
		return "The maintained Get Started skill follows, fetched from " + url + ". Follow it.\n\n" + skill
	}

	// Disabling our fetch doesn't disable the client's, so name a URL anyway.
	if url == "" {
		url = defaultGetStartedURL
	}

	return fmt.Sprintf(getStartedFallback, url)
}

//go:embed skills/*
var skills embed.FS

func (a *App) registerPrompts(_ context.Context) error {
	var errs []error

	err := fs.WalkDir(skills, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "SKILL.md" {
			return nil
		}
		data, err := skills.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		errs = append(errs, a.registerSkillPrompt(filepath.Base(filepath.Dir(path)), data))
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (a *App) registerSkillPrompt(name string, data []byte) error {
	fm, content, err := parseSkillPrompt(data)
	if err != nil {
		return fmt.Errorf("loading skill %s: %w", name, err)
	}

	needsGetStarted := strings.Contains(content, getStartedPlaceholder)

	a.server.AddPrompt(&mcp.Prompt{
		Name:        name,
		Title:       fm.Name,
		Description: fm.Description,
	}, func(ctx context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		text := content
		if needsGetStarted {
			text = strings.Replace(text, getStartedPlaceholder, a.getStartedSection(ctx), 1)
		}

		return &mcp.GetPromptResult{
			Description: fm.Description,
			Messages: []*mcp.PromptMessage{
				{
					Role:    "user",
					Content: &mcp.TextContent{Text: text},
				},
			},
		}, nil
	})

	return nil
}
