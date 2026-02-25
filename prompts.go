package fpmcpserver

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

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

	a.server.AddPrompt(&mcp.Prompt{
		Name:        name,
		Title:       fm.Name,
		Description: fm.Description,
	}, func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: fm.Description,
			Messages: []*mcp.PromptMessage{
				{
					Role:    "user",
					Content: &mcp.TextContent{Text: content},
				},
			},
		}, nil
	})

	return nil
}
