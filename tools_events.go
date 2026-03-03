package fpmcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetEventInput defines the input schema for the get_event tool
type GetEventInput struct {
	EventID  string   `json:"event_id" jsonschema:"The unique identifier of the identification event to retrieve"`
	Products []string `json:"products,omitempty" jsonschema:"Optional list of product fields to include in the response. If omitted all products are returned."`
}

// GetEventOutput defines the output schema for the get_event tool.
// Use `ref` tag to reference OpenAPI schemas, `description` tag for inline descriptions.
type GetEventOutput struct {
	Event sdk.EventsGetResponse `json:"event" ref:"EventsGetResponse"`
}

type SearchEventsOutput struct {
	Events sdk.SearchEventsResponse `json:"events" ref:"SearchEventsResponse"`
}

func (a *App) requireServerApiClient(ctx context.Context, reqExtra *mcp.RequestExtra) (*sdk.APIClient, context.Context, error) {
	var apiKey string
	if a.cfg.PublicMode {
		apiKey = reqExtra.TokenInfo.Extra[tokenExtraServerApiKey].(string)
	} else {
		apiKey = a.cfg.ServerAPIKey
	}
	if apiKey == "" {
		return nil, nil, errors.New("server API key is required")
	}

	var region string
	if a.cfg.PublicMode {
		region = reqExtra.TokenInfo.Extra[tokenExtraRegionKey].(string)
	} else {
		region = a.cfg.Region
	}
	if region == "" {
		return nil, nil, errors.New("server API region is required")
	}

	// Initialize Fingerprint SDK client
	fpSDKConfig := sdk.NewConfiguration()

	// Set region based on configuration
	switch region {
	case "eu":
		fpSDKConfig.ChangeRegion(sdk.RegionEU)
	case "ap":
		fpSDKConfig.ChangeRegion(sdk.RegionAsia)
	case "us":
		fpSDKConfig.ChangeRegion(sdk.RegionUS)
	default:
		return nil, nil, fmt.Errorf("unknown region %s, must be one of: us, eu, ap", a.cfg.Region)
	}

	fpSDKCtx := context.WithValue(
		ctx,
		sdk.ContextAPIKey,
		sdk.APIKey{Key: apiKey},
	)

	return sdk.NewAPIClient(fpSDKConfig), fpSDKCtx, nil
}

func (a *App) registerGetEventTool(_ context.Context) error {
	// Register the get_event tool
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "get_event",
		Description:  "Retrieves detailed information about a specific identification event from Fingerprint using its event_id. Returns comprehensive data including visitor_id, browser details, geolocation, bot detection, and various smart signals for fraud detection. For schema, see mcp resource fingerprint://schemas/event",
		OutputSchema: schema.SchemaFromStruct(GetEventOutput{}),
		InputSchema:  schema.PatchProductsEnum(schema.SchemaFromStruct(GetEventInput{})),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GetEventInput) (*mcp.CallToolResult, *GetEventOutput, error) {
		var fpClient *sdk.APIClient
		var fpSDKCtx context.Context
		var err error
		if fpClient, fpSDKCtx, err = a.requireServerApiClient(ctx, req.Extra); err != nil {
			return nil, nil, err
		}
		if input.EventID == "" {
			return nil, nil, errors.New("event_id is required")
		}

		// Call Fingerprint API
		event, _, err := fpClient.FingerprintApi.GetEvent(fpSDKCtx, input.EventID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get event: %w", err)
		}

		schema.FilterProducts(event.Products, input.Products)

		return nil, &GetEventOutput{Event: event}, nil
	})

	return nil
}

func (a *App) registerSearchEventsTool(_ context.Context) error {
	// Register the search_events tool
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "search_events",
		Description:  "Retrieves detailed information about events matching provided criteria. Returns comprehensive data including visitor_id, browser details, geolocation, bot detection, and various smart signals for fraud detection. Output can be large so consider only choosing products that you need and setting the limit to a dozen events or so. For schema of every individual event, see mcp resource fingerprint://schemas/event",
		OutputSchema: schema.SchemaFromStruct(SearchEventsOutput{}),
		InputSchema:  schema.PatchProductsEnum(schema.SearchEventsInputSchema),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input schema.SearchEventInput) (*mcp.CallToolResult, *SearchEventsOutput, error) {
		var fpClient *sdk.APIClient
		var fpSDKCtx context.Context
		var err error
		if fpClient, fpSDKCtx, err = a.requireServerApiClient(ctx, req.Extra); err != nil {
			return nil, nil, err
		}

		limit := input.Limit
		if limit == 0 {
			return nil, nil, fmt.Errorf("limit must be greater than zero")
		}

		// Call Fingerprint API
		events, _, err := fpClient.FingerprintApi.SearchEvents(fpSDKCtx, int32(limit), schema.SearchEventInputToOpts(&input))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to search events: %w", err)
		}

		for i := range events.Events {
			schema.FilterProducts(events.Events[i].Products, input.Products)
		}

		return nil, &SearchEventsOutput{Events: events}, nil
	})

	return nil
}
