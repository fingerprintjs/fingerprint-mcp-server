package fpmcpserver

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListSkillsInput struct{}

type SkillSummary struct {
	ID          string `json:"id" jsonschema:"Skill id, pass it to get_skill"`
	Description string `json:"description" jsonschema:"What the skill covers and when to use it"`
}

type ListSkillsOutput struct {
	Skills []SkillSummary `json:"skills,omitempty" jsonschema:"Available Fingerprint skills"`
}

type GetSkillInput struct {
	ID string `json:"id" jsonschema:"Skill id from list_skills"`
}

type GetSkillOutput struct {
	ID      string   `json:"id" jsonschema:"Skill id"`
	Content string   `json:"content" jsonschema:"The skill's instructions, in Markdown"`
	Files   []string `json:"files" jsonschema:"Other files in the skill, such as snippets the instructions refer to. Fetch one with get_skill_file."`
}

type GetSkillFileInput struct {
	ID   string `json:"id" jsonschema:"Skill id from list_skills"`
	Path string `json:"path" jsonschema:"File path within the skill, as listed in get_skill's files"`
}

type GetSkillFileOutput struct {
	ID      string `json:"id" jsonschema:"Skill id"`
	Path    string `json:"path" jsonschema:"File path within the skill"`
	Content string `json:"content" jsonschema:"File content"`
}

func skillsAnnotations(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		DestructiveHint: utils.Ptr(false),
		IdempotentHint:  true,
		OpenWorldHint:   utils.Ptr(true),
		ReadOnlyHint:    true,
		Title:           title,
	}
}

func skillsUnavailable() (*mcp.CallToolResult, error) {
	return toolError("skills_unavailable", "the Fingerprint skills repo could not be loaded, try again later or read the skills at %s", skillsRepoURL)
}

func (a *App) registerListSkillsTool(_ context.Context) error {
	addTool(a, &mcp.Tool{
		Name:         "list_skills",
		Description:  "Lists Fingerprint skills: step-by-step guides for integrating Fingerprint into a project (per frontend framework and backend language), first-party deployment through a custom subdomain or proxy, Smart Signals, the Rules Engine, tagging and request filtering. Returns ids and descriptions only. Load a skill with get_skill through call_tool.",
		InputSchema:  schema.SchemaFromStruct(ListSkillsInput{}),
		OutputSchema: schema.SchemaFromStruct(ListSkillsOutput{}),
		Annotations:  skillsAnnotations("List Fingerprint Skills"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ ListSkillsInput) (*mcp.CallToolResult, *ListSkillsOutput, error) {
		logger := a.opts.logger()
		index, err := a.skills.index(ctx, logger)
		if err != nil {
			res, err := skillsUnavailable()
			return res, nil, err
		}

		out := &ListSkillsOutput{Skills: make([]SkillSummary, 0, len(index))}
		for id := range index {
			out.Skills = append(out.Skills, SkillSummary{ID: id})
		}
		sort.Slice(out.Skills, func(i, j int) bool { return out.Skills[i].ID < out.Skills[j].ID })

		var wg sync.WaitGroup
		for i := range out.Skills {
			wg.Go(func() {
				content, ok := a.skills.file(ctx, logger, out.Skills[i].ID, skillFileName)
				if !ok {
					return
				}
				if fm, err := parseFrontmatter([]byte(content)); err == nil {
					out.Skills[i].Description = fm.Description
				}
			})
		}
		wg.Wait()

		return nil, out, nil
	})

	return nil
}

func (a *App) registerGetSkillTool(_ context.Context) error {
	addHiddenTool(a, &mcp.Tool{
		Name:         "get_skill",
		Description:  "Returns one Fingerprint skill's instructions by id, plus the other files in the skill. Fetch those with get_skill_file.",
		InputSchema:  schema.SchemaFromStruct(GetSkillInput{}),
		OutputSchema: schema.SchemaFromStruct(GetSkillOutput{}),
		Annotations:  skillsAnnotations("Get Fingerprint Skill"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input GetSkillInput) (*mcp.CallToolResult, *GetSkillOutput, error) {
		logger := a.opts.logger()
		index, err := a.skills.index(ctx, logger)
		if err != nil {
			res, err := skillsUnavailable()
			return res, nil, err
		}
		files, ok := index[input.ID]
		if !ok {
			res, err := toolError("skill_not_found", "%q is not a Fingerprint skill: call list_skills to see what is available", input.ID)
			return res, nil, err
		}

		content, ok := a.skills.file(ctx, logger, input.ID, skillFileName)
		if !ok {
			res, err := skillsUnavailable()
			return res, nil, err
		}

		return nil, &GetSkillOutput{
			ID:      input.ID,
			Content: stripFrontmatter(content),
			Files:   slices.DeleteFunc(slices.Clone(files), func(f string) bool { return f == skillFileName }),
		}, nil
	})

	return nil
}

func (a *App) registerGetSkillFileTool(_ context.Context) error {
	addHiddenTool(a, &mcp.Tool{
		Name:         "get_skill_file",
		Description:  "Returns a file from a Fingerprint skill, such as a code snippet its instructions refer to, by skill id and path.",
		InputSchema:  schema.SchemaFromStruct(GetSkillFileInput{}),
		OutputSchema: schema.SchemaFromStruct(GetSkillFileOutput{}),
		Annotations:  skillsAnnotations("Get Fingerprint Skill File"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input GetSkillFileInput) (*mcp.CallToolResult, *GetSkillFileOutput, error) {
		logger := a.opts.logger()
		index, err := a.skills.index(ctx, logger)
		if err != nil {
			res, err := skillsUnavailable()
			return res, nil, err
		}
		files, ok := index[input.ID]
		if !ok {
			res, err := toolError("skill_not_found", "%q is not a Fingerprint skill: call list_skills to see what is available", input.ID)
			return res, nil, err
		}
		if !slices.Contains(files, input.Path) {
			res, err := toolError("skill_file_not_found", "%q is not a file in skill %q: call get_skill to see its files", input.Path, input.ID)
			return res, nil, err
		}

		content, ok := a.skills.file(ctx, logger, input.ID, input.Path)
		if !ok {
			res, err := skillsUnavailable()
			return res, nil, err
		}

		return nil, &GetSkillFileOutput{ID: input.ID, Path: input.Path, Content: content}, nil
	})

	return nil
}
