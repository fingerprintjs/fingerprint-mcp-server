package fpmcpserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// skillFrontmatter holds the YAML frontmatter parsed from a SKILL.md file.
type skillFrontmatter struct {
	Name        string
	Description string
}

// parseSkillFile reads a SKILL.md file and extracts the YAML frontmatter
// and the full file content.
func parseSkillFile(path string) (*skillFrontmatter, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading skill file: %w", err)
	}

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

func (a *App) registerPrompts(_ context.Context) error {
	errs := []error{
		a.registerSkillPrompt("skills/onboarding/SKILL.md"),
	}

	return errors.Join(errs...)
}

func (a *App) registerSkillPrompt(skillPath string) error {
	absPath, err := filepath.Abs(skillPath)
	if err != nil {
		return fmt.Errorf("resolving skill path: %w", err)
	}

	fm, content, err := parseSkillFile(absPath)
	if err != nil {
		return fmt.Errorf("loading skill %s: %w", skillPath, err)
	}

	a.server.AddPrompt(&mcp.Prompt{
		Name:        filepath.Base(filepath.Dir(skillPath)),
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
