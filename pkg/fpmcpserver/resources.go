package fpmcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
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
		Description: "Detailed information about a specific identification event from Fingerprint using its event_id. Contains comprehensive data including visitor_id, browser details, geolocation, bot detection, and various smart signals for fraud detection. For schema, see mcp resource fingerprint://schemas/event",
		MIMEType:    "application/json",
		Name:        "identification_event",
		Title:       "Identification Event",
		URITemplate: uriTemplate,
		Icons:       nil,
	}, func(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		uriValues := tmpl.Match(request.Params.URI)
		if uriValues == nil {
			// this should never happen because we can only get here if uri matches the template
			return nil, fmt.Errorf("could not parse resource uri")
		}

		var fpClient *sdk.APIClient
		var fpSDKCtx context.Context
		var err error
		if fpClient, fpSDKCtx, err = a.requireServerApiClient(ctx, request.Extra.Header); err != nil {
			return nil, err
		}

		// Call Fingerprint API
		event, _, fpErr := fpClient.FingerprintApi.GetEvent(fpSDKCtx, uriValues.Get("event_id").String())
		if fpErr != nil {
			return nil, fmt.Errorf("failed to get event: %w", fpErr)
		}

		bytes, err := json.Marshal(event)
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
	content := schema.SchemaFromStruct(GetEventOutput{})

	a.server.AddResource(&mcp.Resource{
		Description: "JSON Schema for identification events",
		MIMEType:    "application/schema+json",
		Name:        "identification_event_schema",
		Title:       "Identification Event JSON Schema",
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
