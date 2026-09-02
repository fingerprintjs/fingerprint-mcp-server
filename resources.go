package fpmcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"
)

func (a *App) registerEventResource(_ context.Context) error {
	uriTemplate := "fingerprint://events/{event_id}"
	tmpl, err := uritemplate.New(uriTemplate)
	if err != nil {
		return fmt.Errorf("parsing uri template: %w", err)
	}

	a.server.AddResourceTemplate(&mcp.ResourceTemplate{
		Description: "A single Fingerprint event by event_id, of either kind. An identification event, collected by the JS Agent or a mobile SDK, contains visitor_id, browser and device details, geolocation, and the full smart signal set. An Automation Intelligence (edge) event, observed server-side with no client agent, contains only request and IP derived fields (ip_info, proxy, vpn, bot_info, url, tags, timestamp) and has no visitor_id. For schema, see mcp resource fingerprint://schemas/event",
		MIMEType:    "application/json",
		Name:        "event",
		Title:       "Fingerprint Event",
		URITemplate: uriTemplate,
		Icons:       nil,
	}, func(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		uriValues := tmpl.Match(request.Params.URI)
		if uriValues == nil {
			// this should never happen because we can only get here if uri matches the template
			return nil, fmt.Errorf("could not parse resource uri")
		}

		fpClient, err := a.requireFingerprintClient(ctx, request.Extra)
		if err != nil {
			return nil, err
		}

		// Call Fingerprint API
		event, _, fpErr := fpClient.GetEvent(ctx, uriValues.Get("event_id").String())
		if fpErr != nil {
			return nil, wrapFPError("failed to get event", fpErr)
		}

		schema.StripAdditionalProperties(event)
		// Same conversion the get_event tool applies, so the two paths can't
		// disagree about what a timestamp looks like.
		bytes, err := json.Marshal(schema.ReadableTimestamps(event))
		if err != nil {
			return nil, fmt.Errorf("could not serialize event into json")
		}

		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      request.Params.URI,
					MIMEType: "application/json",
					Text:     string(bytes),
				},
			},
		}, nil
	})

	return nil
}

func (a *App) registerEnvironmentSchemaResource(_ context.Context) error {
	content := schema.MustInferSchema[CreateEnvironmentOutput]()

	a.server.AddResource(&mcp.Resource{
		Description: "JSON Schema for environment objects returned by environment management tools",
		MIMEType:    "application/schema+json",
		Name:        "environment_schema",
		Title:       "Environment JSON Schema",
		URI:         "fingerprint://schemas/environment",
	}, func(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      request.Params.URI,
					MIMEType: "application/schema+json",
					Text:     string(content),
				},
			},
		}, nil
	})

	return nil
}

func (a *App) registerAPIKeySchemaResource(_ context.Context) error {
	content := schema.MustInferSchema[GetAPIKeyOutput]()

	a.server.AddResource(&mcp.Resource{
		Description: "JSON Schema for API key objects returned by API key management tools",
		MIMEType:    "application/schema+json",
		Name:        "api_key_schema",
		Title:       "API Key JSON Schema",
		URI:         "fingerprint://schemas/api-key",
	}, func(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      request.Params.URI,
					MIMEType: "application/schema+json",
					Text:     string(content),
				},
			},
		}, nil
	})

	return nil
}

func (a *App) registerEventSchemaResource(_ context.Context) error {
	content := schema.PatchTimestampFormat(schema.SchemaFromStruct(GetEventOutput{}))

	a.server.AddResource(&mcp.Resource{
		Description: "JSON Schema for Fingerprint events. One flat shape covers both kinds and every property is optional: an Automation Intelligence (edge) event populates only the request and IP derived ones (ip_info, proxy, vpn, bot_info, url, tags, timestamp), never visitor_id or device details.",
		MIMEType:    "application/schema+json",
		Name:        "event_schema",
		Title:       "Fingerprint Event JSON Schema",
		URI:         "fingerprint://schemas/event",
	}, func(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      request.Params.URI,
					MIMEType: "application/schema+json",
					Text:     string(content),
				},
			},
		}, nil
	})

	return nil
}
