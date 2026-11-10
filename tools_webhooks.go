package fpmcpserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/mgmtapi"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// signingKeyWarning goes out with the one response that carries a signing key.
const signingKeyWarning = "signing_key is shown only once: the API will not return it again and it cannot be viewed later. Tell the user to store it now, somewhere secret, for verifying the FPJS-Event-Signature header. A lost key can only be replaced by creating a new webhook and deleting this one."

// WebhookView is a webhook as the tools return it. It leaves out the legacy
// basic-auth credentials, reporting only whether they are set, and carries no
// signing key: create_webhook adds that alongside, the one time the API sends it.
type WebhookView struct {
	ID                  string     `json:"id" jsonschema:"Auto-generated webhook identifier"`
	Description         string     `json:"description" jsonschema:"Webhook description"`
	Status              string     `json:"status" jsonschema:"Webhook status. Values: enabled, disabled"`
	Verified            bool       `json:"verified" jsonschema:"Whether the endpoint has been verified. Unverified webhooks receive no events: run verify_webhook"`
	Environment         any        `json:"environment" jsonschema:"Associated environment. Null for workspace-scoped (global) webhooks"`
	URL                 string     `json:"url" jsonschema:"Webhook endpoint URL"`
	Legacy              bool       `json:"legacy" jsonschema:"Whether this is a legacy webhook"`
	BasicAuthConfigured bool       `json:"basic_auth_configured" jsonschema:"Whether legacy basic authentication is set. The credentials themselves are never returned"`
	CreatedAt           time.Time  `json:"created_at" jsonschema:"Timestamp when the webhook was created"`
	LastEnabledAt       *time.Time `json:"last_enabled_at" jsonschema:"Timestamp when the webhook was last enabled"`
	LastDisabledAt      *time.Time `json:"last_disabled_at" jsonschema:"Timestamp when the webhook was last disabled"`
}

func newWebhookView(w mgmtapi.Webhook) WebhookView {
	return WebhookView{
		ID:                  w.ID,
		Description:         w.Description,
		Status:              w.Status,
		Verified:            w.Verified,
		Environment:         w.Environment,
		URL:                 w.URL,
		Legacy:              w.Legacy,
		BasicAuthConfigured: basicAuthConfigured(w.BasicAuth),
		CreatedAt:           w.CreatedAt,
		LastEnabledAt:       w.LastEnabledAt,
		LastDisabledAt:      w.LastDisabledAt,
	}
}

// basicAuthConfigured treats an empty object like null: non-legacy webhooks
// may send either, and neither means credentials are set.
func basicAuthConfigured(v any) bool {
	switch auth := v.(type) {
	case nil:
		return false
	case map[string]any:
		return len(auth) > 0
	default:
		return true
	}
}

type ListWebhooksInput struct {
	Status      string `json:"status,omitempty" jsonschema:"Filter by webhook status. Values: enabled, disabled"`
	Environment string `json:"environment,omitempty" jsonschema:"Filter by environment ID"`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Pagination cursor from the previous response"`
	Limit       int    `json:"limit,omitempty" jsonschema:"Maximum items per page (0-101, default: 10)"`
}

type ListWebhooksOutput struct {
	Webhooks   []WebhookView              `json:"webhooks" jsonschema:"Webhooks on this page"`
	Pagination mgmtapi.PaginationMetadata `json:"pagination" jsonschema:"Pass next_cursor as cursor to get the next page"`
}

type WebhookIDInput struct {
	ID string `json:"id" jsonschema:"Webhook identifier, e.g. wh_HYv9YfsIIUjpvR"`
}

type GetWebhookInput = WebhookIDInput

type VerifyWebhookInput = WebhookIDInput

type DeleteWebhookInput = WebhookIDInput

type CreateWebhookInput struct {
	URL         string `json:"url" jsonschema:"Webhook endpoint URL. Must start with https://"`
	Description string `json:"description,omitempty" jsonschema:"Webhook description"`
	Status      string `json:"status,omitempty" jsonschema:"Initial status. Values: enabled, disabled"`
	Environment string `json:"environment,omitempty" jsonschema:"Environment ID to scope the webhook to. Omit for a workspace-scoped (global) webhook that receives events from every environment"`
}

type CreateWebhookOutput struct {
	Webhook    WebhookView `json:"webhook" jsonschema:"The created webhook. It sends no events until verified with verify_webhook"`
	SigningKey string      `json:"signing_key,omitempty" jsonschema:"Key for verifying webhook signatures. Present only when signatures are enabled for the workspace, and only in this response"`
	Warning    string      `json:"warning,omitempty" jsonschema:"Set when signing_key is present: it will not be shown again"`
}

type UpdateWebhookInput struct {
	ID          string  `json:"id" jsonschema:"Webhook identifier"`
	URL         *string `json:"url,omitempty" jsonschema:"New endpoint URL. Must start with https://. The webhook must be verified again afterwards"`
	Description *string `json:"description,omitempty" jsonschema:"New webhook description"`
	Status      *string `json:"status,omitempty" jsonschema:"Enable or disable sending events. Values: enabled, disabled"`
}

type WebhookOutput struct {
	Webhook WebhookView `json:"webhook" jsonschema:"The webhook"`
}

func webhookToolError(err error) (*mcp.CallToolResult, error) {
	var apiErr *mgmtapi.APIError
	if !errors.As(err, &apiErr) {
		return nil, err
	}
	details := *apiErr
	if details.StatusCode == http.StatusUnauthorized {
		details.Message += ". Check the Management API key, or reconnect the Fingerprint connector."
	}
	return apiErrorResult(details)
}

func (a *App) registerListWebhooksTool(_ context.Context) error {
	addTool(a, &mcp.Tool{
		Name:        "list_webhooks",
		Description: "Lists the workspace's webhooks with optional status (enabled/disabled) and environment filters. Supports pagination.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "List Webhooks",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListWebhooksInput) (*mcp.CallToolResult, *ListWebhooksOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		resp, err := client.ListWebhooks(ctx,
			&mgmtapi.ListWebhooksParams{Status: input.Status, Environment: input.Environment},
			&mgmtapi.PaginationParams{Cursor: input.Cursor, Limit: input.Limit},
		)
		if err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		out := &ListWebhooksOutput{Webhooks: make([]WebhookView, 0, len(resp.Data)), Pagination: resp.Metadata.Pagination}
		for _, w := range resp.Data {
			out.Webhooks = append(out.Webhooks, newWebhookView(w))
		}
		return nil, out, nil
	})
	return nil
}

func (a *App) registerGetWebhookTool(_ context.Context) error {
	addTool(a, &mcp.Tool{
		Name:        "get_webhook",
		Description: "Gets a webhook by its ID: URL, status, verification state and environment. The signing key is never returned here; it is shown only once, by create_webhook.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "Get Webhook",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GetWebhookInput) (*mcp.CallToolResult, *WebhookOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}
		w, err := client.GetWebhook(ctx, input.ID)
		if err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		return nil, &WebhookOutput{Webhook: newWebhookView(*w)}, nil
	})
	return nil
}

func (a *App) registerCreateWebhookTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "create_webhook",
		Description: "Creates a webhook that receives identification events at an https:// URL. Pass environment to scope it to one environment; omit it for a global webhook. The webhook sends nothing until verify_webhook succeeds. When webhook signatures are enabled, the response includes signing_key, which is shown only this once: hand it to the user to store.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Create Webhook",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CreateWebhookInput) (*mcp.CallToolResult, *CreateWebhookOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.URL == "" {
			return nil, nil, errors.New("url is required")
		}
		create := mgmtapi.CreateWebhookRequest{
			URL:         input.URL,
			Description: input.Description,
			Status:      input.Status,
		}
		// Left nil rather than "" when omitted, so the field stays out of the body.
		if input.Environment != "" {
			create.Environment = input.Environment
		}
		w, err := client.CreateWebhook(ctx, create)
		if err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		out := &CreateWebhookOutput{Webhook: newWebhookView(*w)}
		if w.SigningKey != "" {
			out.SigningKey = w.SigningKey
			out.Warning = signingKeyWarning
		}
		return nil, out, nil
	})
	return nil
}

func (a *App) registerUpdateWebhookTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "update_webhook",
		Description: "Updates a webhook's URL, description or status (enabled/disabled). Only provided fields change. Changing the URL requires verifying the webhook again. Changes take effect within a few minutes. The environment scope cannot be changed.",
		Annotations: &mcp.ToolAnnotations{
			// Overwrites the fields it is given, and disabling stops event delivery.
			DestructiveHint: utils.Ptr(true),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Update Webhook",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateWebhookInput) (*mcp.CallToolResult, *WebhookOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}
		if input.URL == nil && input.Description == nil && input.Status == nil {
			return nil, nil, errors.New("nothing to update: pass url, description or status")
		}
		w, err := client.UpdateWebhook(ctx, input.ID, mgmtapi.UpdateWebhookRequest{
			URL:         input.URL,
			Description: input.Description,
			Status:      input.Status,
		})
		if err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		return nil, &WebhookOutput{Webhook: newWebhookView(*w)}, nil
	})
	return nil
}

func (a *App) registerVerifyWebhookTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "verify_webhook",
		Description: "Sends a mocked test event to the webhook's URL. The endpoint must answer HTTP 200 for the webhook to become verified and start receiving events. Returns a 400 error if the webhook is already verified. Use get_webhook to check the verified state afterwards.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			// Fingerprint sends a request to the user's endpoint.
			OpenWorldHint: utils.Ptr(true),
			ReadOnlyHint:  false,
			Title:         "Verify Webhook",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input VerifyWebhookInput) (*mcp.CallToolResult, *WebhookOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}
		w, err := client.VerifyWebhook(ctx, input.ID)
		if err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		return nil, &WebhookOutput{Webhook: newWebhookView(*w)}, nil
	})
	return nil
}

func (a *App) registerDeleteWebhookTool(_ context.Context) error {
	addDirectTool(a, &mcp.Tool{
		Name:        "delete_webhook",
		Description: "Deletes a webhook. This operation is irreversible, and event delivery stops within a few minutes.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(true),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Delete Webhook",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DeleteWebhookInput) (*mcp.CallToolResult, *struct{}, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}
		if err := client.DeleteWebhook(ctx, input.ID); err != nil {
			result, err := webhookToolError(err)
			return result, nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Webhook deleted successfully"}}}, nil, nil
	})
	return nil
}
