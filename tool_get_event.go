package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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

func (a *App) registerGetEventTool(_ context.Context) error {
	// Register the get_event tool
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "get_event",
		Description:  "Retrieves detailed information about a specific identification event from Fingerprint using its event_id. Returns comprehensive data including visitor_id, browser details, geolocation, bot detection, and various smart signals for fraud detection. For schema, see mcp resource fingerprint://schemas/event",
		OutputSchema: schemaFromStruct(GetEventOutput{}),
		InputSchema:  patchProductsEnum(schemaFromStruct(GetEventInput{})),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GetEventInput) (*mcp.CallToolResult, *GetEventOutput, error) {
		if input.EventID == "" {
			return nil, nil, errors.New("event_id is required")
		}

		fpSDKCtx := context.WithValue(
			ctx,
			sdk.ContextAPIKey,
			sdk.APIKey{Key: a.config.APIKey},
		)

		// Call Fingerprint API
		event, _, err := a.fpClient.FingerprintApi.GetEvent(fpSDKCtx, input.EventID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get event: %w", err)
		}

		filterProducts(event.Products, input.Products)

		return nil, &GetEventOutput{Event: event}, nil
	})

	return nil
}

func (a *App) registerSearchEventsTool(_ context.Context) error {
	// Register the search_events tool
	mcp.AddTool(a.server, &mcp.Tool{
		Name:         "search_events",
		Description:  "Retrieves detailed information about events matching provided criteria. Returns comprehensive data including visitor_id, browser details, geolocation, bot detection, and various smart signals for fraud detection. Output can be large so consider only choosing products that you need and setting the limit to a dozen events or so. For schema of every individual event, see mcp resource fingerprint://schemas/event",
		OutputSchema: schemaFromStruct(SearchEventsOutput{}),
		InputSchema:  patchProductsEnum(searchEventsInputSchema),
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SearchEventInput) (*mcp.CallToolResult, *SearchEventsOutput, error) {
		fpSDKCtx := context.WithValue(
			ctx,
			sdk.ContextAPIKey,
			sdk.APIKey{Key: a.config.APIKey},
		)

		limit := input.Limit
		if limit == 0 {
			return nil, nil, fmt.Errorf("limit must be greater than zero")
		}

		// Call Fingerprint API
		events, _, err := a.fpClient.FingerprintApi.SearchEvents(fpSDKCtx, int32(limit), searchEventInputToOpts(&input))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to search events: %w", err)
		}

		for i := range events.Events {
			filterProducts(events.Events[i].Products, input.Products)
		}

		return nil, &SearchEventsOutput{Events: events}, nil
	})

	return nil
}

// searchEventInputToOpts copies matching fields from SearchEventInput to
// sdk.FingerprintApiSearchEventsOpts using reflection. Fields like Limit and
// Products that exist only in SearchEventInput are skipped automatically.
func searchEventInputToOpts(input *SearchEventInput) *sdk.FingerprintApiSearchEventsOpts {
	opts := &sdk.FingerprintApiSearchEventsOpts{}
	src := reflect.ValueOf(input).Elem()
	dst := reflect.ValueOf(opts).Elem()
	for i := 0; i < dst.NumField(); i++ {
		name := dst.Type().Field(i).Name
		srcField := src.FieldByName(name)
		if srcField.IsValid() && srcField.Type().AssignableTo(dst.Field(i).Type()) {
			dst.Field(i).Set(srcField)
		}
	}
	return opts
}
