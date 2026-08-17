package fpmcpserver

import (
	"context"
	"encoding/json"
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
	mutating    bool
	call        func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error)
}

// inputSchemaFor returns the schema list_tools should report. A tool may leave
// InputSchema unset and let AddTool infer it from In, but AddTool infers into
// its own copy, so reading it back off the caller's tool yields nothing.
func inputSchemaFor[In any](t *mcp.Tool) any {
	if t.InputSchema != nil {
		return t.InputSchema
	}
	var zero In
	return schema.SchemaFromStruct(zero)
}

// dispatchFunc adapts a typed handler so a proxy can invoke it from raw JSON,
// reproducing what AddTool does with the handler's output.
func dispatchFunc[In, Out any](name string, h mcp.ToolHandlerFor[In, Out]) func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args json.RawMessage) (*mcp.CallToolResult, error) {
		var in In
		if len(args) > 0 {
			if err := json.Unmarshal(args, &in); err != nil {
				return toolError("invalid_arguments", "could not read the arguments for %s: %v", name, err)
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
			return nil, fmt.Errorf("marshaling %s output: %w", name, err)
		}
		res.StructuredContent = json.RawMessage(outJSON)
		if res.Content == nil {
			res.Content = []mcp.Content{&mcp.TextContent{Text: string(outJSON)}}
		}
		return res, nil
	}
}

// addTool registers a read-only tool, reachable through call_tool.
func addTool[In, Out any](a *App, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(a.server, t, h)

	a.tools = append(a.tools, registeredTool{
		name:        t.Name,
		description: t.Description,
		inputSchema: inputSchemaFor[In](t),
		call:        dispatchFunc(t.Name, h),
	})
}

// addWriteTool registers a tool that changes state. It is reachable through
// call_write_tool but never through call_tool: annotations are per tool, and a
// proxy that ran both could not be honestly annotated for either, so a client
// auto-approving read-only tools would end up auto-running mutations.
func addWriteTool[In, Out any](a *App, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(a.server, t, h)

	a.tools = append(a.tools, registeredTool{
		name:        t.Name,
		description: t.Description,
		inputSchema: inputSchemaFor[In](t),
		mutating:    true,
		call:        dispatchFunc(t.Name, h),
	})
}

// toolError reports a refusal as a tool result rather than a protocol error.
// A protocol error reaches the model as its client's generic failure text, so
// "you may not run this" would read the same as "this tool is broken". The
// {code, message} shape matches what the Fingerprint API returns, so a caller
// can read a dispatch failure the same way it reads an upstream one.
func toolError(code, format string, args ...any) (*mcp.CallToolResult, error) {
	message := fmt.Sprintf(format, args...)
	body, err := json.Marshal(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %s", code, message)
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}, nil
}

func proxyFor(mutating bool) string {
	if mutating {
		return "call_write_tool"
	}
	return "call_tool"
}

func (a *App) lookupTool(name string) *registeredTool {
	for i := range a.tools {
		if a.tools[i].name == name {
			return &a.tools[i]
		}
	}
	return nil
}

type ListToolsInput struct {
	ToolName string `json:"tool_name,omitempty" jsonschema:"Optional tool name. When set, the response also includes that tool's input schema."`
}

type ListedTool struct {
	Name        string         `json:"name" jsonschema:"Tool name"`
	Description string         `json:"description" jsonschema:"What the tool does"`
	Mutating    bool           `json:"mutating" jsonschema:"Whether the tool changes state. Confirm with the user before running one of these."`
	RunWith     string         `json:"run_with" jsonschema:"Which proxy runs this tool: call_tool for read-only tools, call_write_tool for tools that change state."`
	InputSchema map[string]any `json:"input_schema,omitempty" jsonschema:"JSON Schema for the tool's arguments, included only when tool_name was set"`
}

type ListToolsOutput struct {
	Tools []ListedTool `json:"tools" jsonschema:"Tools this server is serving right now"`
}

type CallToolInput struct {
	ToolName  string         `json:"tool_name" jsonschema:"Name of the tool to run, as returned by list_tools"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Arguments for that tool, matching the input schema from list_tools"`
}

func (a *App) registerListToolsTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "list_tools",
		Description:  "Lists the Fingerprint tools this server is serving right now. Use this when you are unsure which tools exist, or when a tool you expect is not in your available tools: your list can be out of date. Each tool names the proxy that runs it in run_with. Pass tool_name to also get that tool's input schema.",
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
			listed := ListedTool{Name: t.name, Description: t.description, Mutating: t.mutating, RunWith: proxyFor(t.mutating)}
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
				return toolError("invalid_arguments", "could not read the arguments: %v", err)
			}
		}
		if input.ToolName == "" {
			return toolError("invalid_arguments", "tool_name is required")
		}

		target := a.lookupTool(input.ToolName)
		switch {
		case target == nil:
			return toolError("tool_not_found", "%q is not a tool on this server: call list_tools to see what is available", input.ToolName)
		case target.mutating:
			return toolError("tool_is_mutating", "%q changes state, so it cannot be run through call_tool: use call_write_tool, which asks for your approval first", input.ToolName)
		}

		var args json.RawMessage
		if input.Arguments != nil {
			encoded, err := json.Marshal(input.Arguments)
			if err != nil {
				return toolError("invalid_arguments", "could not read the arguments for %s: %v", input.ToolName, err)
			}
			args = encoded
		}

		return target.call(ctx, req, args)
	})

	return nil
}

type CallWriteToolInput struct {
	ToolName  string         `json:"tool_name" jsonschema:"Name of the state-changing tool to run, as returned by list_tools with mutating true"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"Arguments for that tool, matching the input schema from list_tools"`
}

// registerCallWriteToolTool exists because annotations are per tool. call_tool
// is annotated read-only so clients can treat it as safe; routing writes
// through it would make that a lie. A separate proxy can be annotated
// destructive, so a client's approval policy stays accurate and an "always
// allow" on reads never silently covers a mutation.
func (a *App) registerCallWriteToolTool(_ context.Context) error {
	a.server.AddTool(&mcp.Tool{
		Name:        "call_write_tool",
		Description: "Runs one of this server's state-changing tools by name. Use this when list_tools reports a tool with mutating true that is not in your own list of available tools. Confirm with the user before calling this, and pass arguments matching the tool's input schema from list_tools.",
		InputSchema: schema.SchemaFromStruct(CallWriteToolInput{}),
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(true),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Call Write Tool",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var input CallWriteToolInput
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &input); err != nil {
				return toolError("invalid_arguments", "could not read the arguments: %v", err)
			}
		}
		if input.ToolName == "" {
			return toolError("invalid_arguments", "tool_name is required")
		}

		target := a.lookupTool(input.ToolName)
		switch {
		case target == nil:
			return toolError("tool_not_found", "%q is not a tool on this server: call list_tools to see what is available", input.ToolName)
		case !target.mutating:
			return toolError("tool_is_read_only", "%q does not change state, so run it with call_tool instead", input.ToolName)
		}

		var args json.RawMessage
		if input.Arguments != nil {
			encoded, err := json.Marshal(input.Arguments)
			if err != nil {
				return toolError("invalid_arguments", "could not read the arguments for %s: %v", input.ToolName, err)
			}
			args = encoded
		}

		return target.call(ctx, req, args)
	})

	return nil
}
