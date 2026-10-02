package fpmcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type skillFrontmatter struct {
	Name        string
	Description string
}

func parseFrontmatter(data []byte) (*skillFrontmatter, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "---" {
		return nil, errors.New("missing opening frontmatter delimiter")
	}

	fm := &skillFrontmatter{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "---" {
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
			fm.Description = strings.Trim(strings.TrimSpace(value), `"'`)
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

const (
	defaultSkillsTreeURL = "https://api.github.com/repos/fingerprintjs/skills/git/trees/main?recursive=1"
	defaultSkillsRawURL  = "https://raw.githubusercontent.com/fingerprintjs/skills/main/"
	skillsRepoURL        = "https://github.com/fingerprintjs/skills"

	skillsDir     = "skills/"
	skillFileName = "SKILL.md"
)

const (
	skillsTTL        = time.Hour
	skillsRetryAfter = time.Minute
	skillsTimeout    = 5 * time.Second
	skillsMaxBytes   = 256 << 10
)

var errSkillsUnavailable = errors.New("skills repo unavailable")

type remoteSkill struct {
	url    string
	client *http.Client
	ttl    time.Duration

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

	if time.Now().Before(r.nextRetry) {
		return r.content, r.content != ""
	}

	content, err := r.fetch(ctx)
	if err != nil {
		r.nextRetry = time.Now().Add(skillsRetryAfter)
		if r.content != "" {
			logger.Warn("refetching skills file failed, serving cached copy", "url", r.url, "err", err)
			return r.content, true
		}
		logger.Warn("fetching skills file failed", "url", r.url, "err", err)
		return "", false
	}

	r.content = content
	r.fetchedAt = time.Now()
	r.nextRetry = time.Time{}

	return content, true
}

func (r *remoteSkill) fetch(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, skillsTimeout)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, skillsMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}
	if len(body) > skillsMaxBytes {
		return "", fmt.Errorf("document larger than %d bytes", skillsMaxBytes)
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return "", errors.New("empty document")
	}

	return content, nil
}

type skillsRepo struct {
	rawURL string
	client *http.Client
	ttl    time.Duration
	tree   *remoteSkill

	mu    sync.Mutex
	files map[string]*remoteSkill
}

func newSkillsRepo(treeURL, rawURL string) *skillsRepo {
	if treeURL == "" || rawURL == "" {
		return nil
	}
	if !strings.HasSuffix(rawURL, "/") {
		rawURL += "/"
	}
	return &skillsRepo{
		rawURL: rawURL,
		ttl:    skillsTTL,
		tree:   &remoteSkill{url: treeURL, ttl: skillsTTL},
		files:  map[string]*remoteSkill{},
	}
}

func (s *skillsRepo) index(ctx context.Context, logger *slog.Logger) (map[string][]string, error) {
	if s == nil {
		return nil, errSkillsUnavailable
	}
	raw, ok := s.tree.get(ctx, logger)
	if !ok {
		return nil, errSkillsUnavailable
	}

	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		logger.Warn("parsing skills tree failed", "err", err)
		return nil, errSkillsUnavailable
	}

	files := map[string][]string{}
	for _, e := range tree.Tree {
		if e.Type != "blob" {
			continue
		}
		rest, ok := strings.CutPrefix(e.Path, skillsDir)
		if !ok {
			continue
		}
		id, file, ok := strings.Cut(rest, "/")
		if !ok || id == "" || file == "" {
			continue
		}
		files[id] = append(files[id], file)
	}
	for id, list := range files {
		if !slices.Contains(list, skillFileName) {
			delete(files, id)
			continue
		}
		slices.Sort(list)
	}

	return files, nil
}

func (s *skillsRepo) file(ctx context.Context, logger *slog.Logger, id, name string) (string, bool) {
	path := skillsDir + id + "/" + name

	s.mu.Lock()
	r, ok := s.files[path]
	if !ok {
		r = &remoteSkill{url: s.rawURL + path, client: s.client, ttl: s.ttl}
		s.files[path] = r
	}
	s.mu.Unlock()

	return r.get(ctx, logger)
}
