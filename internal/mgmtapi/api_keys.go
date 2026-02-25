package mgmtapi

import (
	"context"
	"net/url"
	"time"
)

type APIKey struct {
	// ID is the auto-generated API key identifier.
	ID string `json:"id" jsonschema:"Auto-generated API key identifier"`
	// Name is the API key display name.
	Name string `json:"name" jsonschema:"API key display name"`
	// Description is the API key description.
	Description string `json:"description" jsonschema:"API key description"`
	// Status is the API key status. Values: "enabled", "disabled".
	Status string `json:"status" jsonschema:"API key status. Values: enabled, disabled"`
	// Environment is the associated environment. Null if scoped to the workspace.
	Environment any `json:"environment" jsonschema:"Associated environment. Null if scoped to the workspace"`
	// Type is the API key type. Values: "public", "secret", "proxy".
	Type string `json:"type" jsonschema:"API key type. Values: public, secret, proxy"`
	// Token is the API key value. Secret keys are only visible at creation time.
	Token string `json:"token" jsonschema:"API key value. Secret keys are only visible at creation time"`
	// RateLimit is the requests-per-second limit for this key.
	RateLimit float64 `json:"rate_limit" jsonschema:"Requests-per-second limit for this key"`
	// CreatedAt is the timestamp when the API key was created.
	CreatedAt time.Time `json:"created_at" jsonschema:"Timestamp when the API key was created"`
	// DisabledAt is the timestamp when the API key was disabled.
	DisabledAt *time.Time `json:"disabled_at" jsonschema:"Timestamp when the API key was disabled"`
}

type ListAPIKeysParams struct {
	// Type filters by key type. Values: "public", "secret", "proxy".
	Type string
	// Status filters by key status. Values: "enabled", "disabled".
	Status string
	// Environment filters by environment ID.
	Environment string
}

type ListAPIKeysResponse struct {
	Data     []APIKey `json:"data" jsonschema:"List of API keys"`
	Metadata struct {
		Pagination PaginationMetadata `json:"pagination" jsonschema:"Pagination cursors for navigating results"`
	} `json:"metadata" jsonschema:"Response metadata including pagination"`
}

type CreateAPIKeyRequest struct {
	// Type is the API key type. Values: "public", "secret", "proxy".
	Type string `json:"type"`
	// Name is the API key display name (3-255 characters).
	Name string `json:"name"`
	// Description is the API key description (3-255 characters).
	Description string `json:"description,omitempty"`
	// Environment is the environment ID. If omitted for proxy/secret keys, scopes to the workspace.
	Environment string `json:"environment,omitempty"`
}

type UpdateAPIKeyRequest struct {
	// Name is the API key display name (3-255 characters).
	Name *string `json:"name,omitempty"`
	// Description is the API key description (3-255 characters).
	Description *string `json:"description,omitempty"`
	// Status enables or disables the key. Values: "enabled", "disabled".
	Status *string `json:"status,omitempty"`
	// RateLimit is the requests-per-second limit. Minimum: 0.1.
	RateLimit *float64 `json:"rate_limit,omitempty"`
}

type apiKeyResponse struct {
	Data APIKey `json:"data"`
}

func (c *Client) ListAPIKeys(ctx context.Context, params *ListAPIKeysParams, pagination *PaginationParams) (*ListAPIKeysResponse, error) {
	q := url.Values{}
	if params != nil {
		if params.Type != "" {
			q.Set("type", params.Type)
		}
		if params.Status != "" {
			q.Set("status", params.Status)
		}
		if params.Environment != "" {
			q.Set("environment", params.Environment)
		}
	}
	addPaginationParams(q, pagination)

	req, err := c.newRequest(ctx, "GET", "/api-keys", q, nil)
	if err != nil {
		return nil, err
	}

	var resp ListAPIKeysResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetAPIKey(ctx context.Context, id string) (*APIKey, error) {
	req, err := c.newRequest(ctx, "GET", "/api-keys/"+id, nil, nil)
	if err != nil {
		return nil, err
	}

	var resp apiKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateAPIKey(ctx context.Context, input CreateAPIKeyRequest) (*APIKey, error) {
	req, err := c.newRequest(ctx, "POST", "/api-keys", nil, input)
	if err != nil {
		return nil, err
	}

	var resp apiKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateAPIKey(ctx context.Context, id string, input UpdateAPIKeyRequest) (*APIKey, error) {
	req, err := c.newRequest(ctx, "PATCH", "/api-keys/"+id, nil, input)
	if err != nil {
		return nil, err
	}

	var resp apiKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	req, err := c.newRequest(ctx, "DELETE", "/api-keys/"+id, nil, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
