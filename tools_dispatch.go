package fpmcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Some clients bind a conversation's tool catalog when the conversation starts
// and never refresh it, so a tool added later stays invisible there for good.
// Dispatch is not bound that way: a tool missing from the catalog is still
// callable by name. list_tools and call_tool never change, so they stay in
// every catalog and keep the current tool surface reachable through them.
//
// call is nil for tools call_tool must not run.
type registeredTool struct {
	name        string
	description string
	inputSchema any
	call        func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error)
}

// addTool registers a tool and makes it reachable through call_tool. Only
// read-only tools belong here: call_tool hides the real tool name from the
// client, so anything routed through it escapes per-tool approval prompts.
func addTool[In, Out any](a *App, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(a.server, t, h)

	a.tools = append(a.tools, registeredTool{
		name:        t.Name,
		description: t.Description,
		inputSchema: t.InputSchema,
		call: func(ctx context.Context, req *mcp.CallToolRequest, args json.RawMessage) (*mcp.CallToolResult, error) {
			var in In
			if len(args) > 0 {
				if err := json.Unmarshal(args, &in); err != nil {
					return nil, fmt.Errorf("invalid arguments for %s: %w", t.Name, err)
				}
			}

			res, out, err := h(ctx, req, in)
			if err != nil {
				var errRes mcp.CallToolResult
				errRes.SetError(err)
				return &errRes, nil
			}
			if res == nil {
				res = &mcp.CallToolResult{}
			}

			v := reflect.ValueOf(out)
			if !v.IsValid() || (v.Kind() == reflect.Pointer && v.IsNil()) {
				return res, nil
			}
			outJSON, err := json.Marshal(out)
			if err != nil {
				return nil, fmt.Errorf("marshaling %s output: %w", t.Name, err)
			}
			res.StructuredContent = json.RawMessage(outJSON)
			if res.Content == nil {
				res.Content = []mcp.Content{&mcp.TextContent{Text: string(outJSON)}}
			}
			return res, nil
		},
	})
}

// addWriteTool registers a tool that changes state. list_tools reports it so a
// client can tell it exists, but call_tool will not run it: proxying a write
// would hide the real tool name from the client and skip its approval prompt.
func addWriteTool[In, Out any](a *App, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(a.server, t, h)

	a.tools = append(a.tools, registeredTool{
		name:        t.Name,
		description: t.Description,
		inputSchema: t.InputSchema,
	})
}

func (a *App) lookupDispatchable(name string) *registeredTool {
	for i := range a.tools {
		if a.tools[i].name == name && a.tools[i].call != nil {
			return &a.tools[i]
		}
	}
	return nil
}

type ListToolsInput struct {
	ToolName string `json:"tool_name,omitempty" jsonschema:"Optional tool name. When set, the response also includes that tool's input schema."`
}

type ListedTool struct {
	Name         string         `json:"name" jsonschema:"Tool name"`
	Description  string         `json:"description" jsonschema:"What the tool does"`
	Dispatchable bool           `json:"dispatchable" jsonschema:"Whether call_tool can run this tool. Tools that change state are not dispatchable and have to be called directly, so if one is missing from your available tools, start a new conversation to pick it up."`
	InputSchema  map[string]any `json:"input_schema,omitempty" jsonschema:"JSON Schema for the tool's arguments, included only when tool_name was set"`
}

type ListToolsOutput struct {
	Tools []ListedTool `json:"tools" jsonschema:"Tools this server is serving right now"`
}

type CallToolInput struct {
	ToolName  string         `json:"tool_name" jsonschema:"Name of the tool to run, as returned by list_tools with dispatchable true"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Arguments for that tool, matching the input schema from list_tools"`
}

func (a *App) registerListToolsTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "list_tools",
		Description:  "Lists the Fingerprint tools this server is serving right now. Use this when you are unsure which tools exist, or when a tool you expect is not in your available tools: your list can be out of date. Tools marked dispatchable can be run with call_tool. Pass tool_name to also get that tool's input schema.",
		OutputSchema: schema.SchemaFromStruct(ListToolsOutput{}),
		InputSchema:  schema.SchemaFromStruct(ListToolsInput{}),
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "List Tools",
		},
	}, func(_ context.Context, _ *mcp.CallToolRequest, input ListToolsInput) (*mcp.CallToolResult, *ListToolsOutput, error) {
		out := &ListToolsOutput{Tools: make([]ListedTool, 0, len(a.tools))}
		for _, t := range a.tools {
			if input.ToolName != "" && t.name != input.ToolName {
				continue
			}
			listed := ListedTool{Name: t.name, Description: t.description, Dispatchable: t.call != nil}
			if input.ToolName != "" && t.inputSchema != nil {
				encoded, err := json.Marshal(t.inputSchema)
				if err != nil {
					return nil, nil, fmt.Errorf("reading input schema for %s: %w", t.name, err)
				}
				if err := json.Unmarshal(encoded, &listed.InputSchema); err != nil {
					return nil, nil, fmt.Errorf("reading input schema for %s: %w", t.name, err)
				}
			}
			out.Tools = append(out.Tools, listed)
		}

		if input.ToolName != "" && len(out.Tools) == 0 {
			return nil, nil, fmt.Errorf("unknown tool %q: call list_tools without tool_name to see what is available", input.ToolName)
		}
		return nil, out, nil
	})

	return nil
}

func (a *App) registerCallToolTool(_ context.Context) error {
	// Registered untyped so the wrapped tool's result passes through unchanged
	// rather than being re-wrapped in an envelope of call_tool's own.
	a.server.AddTool(&mcp.Tool{
		Name:        "call_tool",
		Description: "Runs one of this server's read-only tools by name. Use this when list_tools reports a dispatchable tool that is not in your own list of available tools. Arguments must match that tool's input schema, which list_tools returns when given a tool_name.",
		InputSchema: schema.SchemaFromStruct(CallToolInput{}),
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "Call Tool",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var input CallToolInput
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &input); err != nil {
				return nil, fmt.Errorf("invalid arguments: %w", err)
			}
		}
		if input.ToolName == "" {
			return nil, errors.New("tool_name is required")
		}

		target := a.lookupDispatchable(input.ToolName)
		if target == nil {
			return nil, fmt.Errorf("%q cannot be run with call_tool: call list_tools to see which tools are dispatchable, and call the others directly", input.ToolName)
		}

		var args json.RawMessage
		if input.Arguments != nil {
			encoded, err := json.Marshal(input.Arguments)
			if err != nil {
				return nil, fmt.Errorf("invalid arguments for %s: %w", input.ToolName, err)
			}
			args = encoded
		}

		return target.call(ctx, req, args)
	})

	return nil
}
