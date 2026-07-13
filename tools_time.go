package fpmcpserver

import (
	"context"
	"fmt"
	"time"

	// Embed the IANA time zone database so LoadLocation resolves named zones
	// even in the minimal alpine runtime image, which ships without tzdata.
	_ "time/tzdata"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetCurrentTimeInput defines the input schema for the get_current_time tool.
type GetCurrentTimeInput struct {
	Timezone string `json:"timezone,omitempty" jsonschema:"Optional IANA timezone name (e.g. \"America/New_York\", \"Europe/London\") to additionally return the current time in that zone. When omitted only UTC is returned."`
}

// GetCurrentTimeOutput defines the output schema for the get_current_time tool.
type GetCurrentTimeOutput struct {
	UTC      string `json:"utc" jsonschema:"Current date and time in UTC, RFC3339 format"`
	Unix     int64  `json:"unix" jsonschema:"Current time as a Unix timestamp in seconds since the epoch"`
	Timezone string `json:"timezone,omitempty" jsonschema:"IANA timezone the local field is expressed in, echoed back when a timezone was requested"`
	Local    string `json:"local,omitempty" jsonschema:"Current date and time in the requested timezone, RFC3339 format"`
}

func (a *App) registerGetCurrentTimeTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "get_current_time",
		Description:  "Returns the current date and time so you never have to guess or infer it from your training data. Always returns UTC; pass an optional IANA timezone to also get the local time in that zone. Use this whenever you need to know the current time, for example to build relative time ranges for search_events.",
		OutputSchema: schema.SchemaFromStruct(GetCurrentTimeOutput{}),
		InputSchema:  schema.SchemaFromStruct(GetCurrentTimeInput{}),
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "Get Current Time",
		},
	}, func(_ context.Context, _ *mcp.CallToolRequest, input GetCurrentTimeInput) (*mcp.CallToolResult, *GetCurrentTimeOutput, error) {
		now := time.Now().UTC()
		out := &GetCurrentTimeOutput{
			UTC:  now.Format(time.RFC3339),
			Unix: now.Unix(),
		}

		if input.Timezone != "" {
			loc, err := time.LoadLocation(input.Timezone)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid timezone %q: must be a valid IANA name such as \"America/New_York\"", input.Timezone)
			}
			out.Timezone = input.Timezone
			out.Local = now.In(loc).Format(time.RFC3339)
		}

		return nil, out, nil
	})

	return nil
}
