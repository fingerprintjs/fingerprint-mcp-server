package mgmtapi

import (
	"context"
	"net/url"
	"time"
)

type Webhook struct {
	// ID is the auto-generated webhook identifier.
	ID string `json:"id" jsonschema:"Auto-generated webhook identifier"`
	// Description is the webhook description.
	Description string `json:"description" jsonschema:"Webhook description"`
	// Status is the webhook status. Values: "enabled", "disabled".
	Status string `json:"status" jsonschema:"Webhook status. Values: enabled, disabled"`
	// Verified indicates whether the webhook URL has been verified.
	Verified bool `json:"verified" jsonschema:"Whether the endpoint has been verified. Unverified webhooks receive no events"`
	// Environment is the associated environment. Null for workspace-scoped webhooks.
	Environment any `json:"environment" jsonschema:"Associated environment. Null for workspace-scoped (global) webhooks"`
	// URL is the webhook endpoint URL. Must start with "https://".
	URL string `json:"url" jsonschema:"Webhook endpoint URL"`
	// Legacy indicates whether this is a legacy webhook.
	Legacy bool `json:"legacy" jsonschema:"Whether this is a legacy webhook"`
	// SigningKey is the key for verifying webhook payloads. Only returned on creation.
	SigningKey string `json:"signing_key,omitempty"`
	// BasicAuth is the legacy basic authentication configuration.
	BasicAuth any `json:"basic_auth"`
	// CreatedAt is the timestamp when the webhook was created.
	CreatedAt time.Time `json:"created_at" jsonschema:"Timestamp when the webhook was created"`
	// LastEnabledAt is the timestamp when the webhook was last enabled.
	LastEnabledAt *time.Time `json:"last_enabled_at" jsonschema:"Timestamp when the webhook was last enabled"`
	// LastDisabledAt is the timestamp when the webhook was last disabled.
	LastDisabledAt *time.Time `json:"last_disabled_at" jsonschema:"Timestamp when the webhook was last disabled"`
}

type ListWebhooksParams struct {
	// Status filters by webhook status. Values: "enabled", "disabled".
	Status string
	// Environment filters by environment ID.
	Environment string
}

type ListWebhooksResponse struct {
	Data     []Webhook `json:"data"`
	Metadata struct {
		Pagination PaginationMetadata `json:"pagination"`
	} `json:"metadata"`
}

type CreateWebhookRequest struct {
	// URL is the webhook endpoint URL. Must start with "https://".
	URL string `json:"url"`
	// Description is the webhook description.
	Description string `json:"description,omitempty"`
	// Status is the webhook status. Values: "enabled", "disabled".
	Status string `json:"status,omitempty"`
	// Environment is the environment ID. Null creates a workspace-scoped webhook.
	Environment any `json:"environment,omitempty"`
}

type UpdateWebhookRequest struct {
	// URL is the webhook endpoint URL. Must start with "https://".
	URL *string `json:"url,omitempty"`
	// Description is the webhook description.
	Description *string `json:"description,omitempty"`
	// Status is the webhook status. Values: "enabled", "disabled".
	Status *string `json:"status,omitempty"`
	// Environment is the environment association.
	Environment any `json:"environment,omitempty"`
}

type webhookResponse struct {
	Data Webhook `json:"data"`
}

func (c *Client) ListWebhooks(ctx context.Context, params *ListWebhooksParams, pagination *PaginationParams) (*ListWebhooksResponse, error) {
	q := url.Values{}
	if params != nil {
		if params.Status != "" {
			q.Set("status", params.Status)
		}
		if params.Environment != "" {
			q.Set("environment", params.Environment)
		}
	}
	addPaginationParams(q, pagination)

	req, err := c.newRequest(ctx, "GET", "/webhooks", q, nil)
	if err != nil {
		return nil, err
	}

	var resp ListWebhooksResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	req, err := c.newRequest(ctx, "GET", "/webhooks/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return nil, err
	}

	var resp webhookResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateWebhook(ctx context.Context, input CreateWebhookRequest) (*Webhook, error) {
	req, err := c.newRequest(ctx, "POST", "/webhooks", nil, input)
	if err != nil {
		return nil, err
	}

	var resp webhookResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateWebhook(ctx context.Context, id string, input UpdateWebhookRequest) (*Webhook, error) {
	req, err := c.newRequest(ctx, "PATCH", "/webhooks/"+url.PathEscape(id), nil, input)
	if err != nil {
		return nil, err
	}

	var resp webhookResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	req, err := c.newRequest(ctx, "DELETE", "/webhooks/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) VerifyWebhook(ctx context.Context, id string) (*Webhook, error) {
	req, err := c.newRequest(ctx, "POST", "/webhooks/"+url.PathEscape(id)+"/verification", nil, nil)
	if err != nil {
		return nil, err
	}

	var resp webhookResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
