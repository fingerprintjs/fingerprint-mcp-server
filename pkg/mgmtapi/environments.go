package mgmtapi

import (
	"context"
	"net/url"
	"time"
)

type Environment struct {
	// ID is the auto-generated environment identifier.
	ID string `json:"id" jsonschema:"Auto-generated environment identifier"`
	// Name is the environment display name.
	Name string `json:"name" jsonschema:"Environment display name"`
	// Description is the environment description (max 256 characters).
	Description string `json:"description" jsonschema:"Environment description (max 256 characters)"`
	// LimitMode is the limit behavior mode. Values: "none", "restrict", "notify".
	LimitMode string `json:"limit_mode" jsonschema:"Limit behavior mode. Values: none, restrict, notify"`
	// LimitValue is the threshold value. Required if LimitMode is not "none". Minimum: 1.
	LimitValue int `json:"limit_value" jsonschema:"Threshold value. Required if limit_mode is not none. Minimum: 1"`
	// IsRestricted indicates whether the environment is currently restricted.
	IsRestricted bool `json:"is_restricted" jsonschema:"Whether the environment is currently restricted"`
	// RestrictedAt is the timestamp when the environment was restricted.
	RestrictedAt *time.Time `json:"restricted_at" jsonschema:"Timestamp when the environment was restricted"`
	// CreatedAt is the timestamp when the environment was created.
	CreatedAt time.Time `json:"created_at" jsonschema:"Timestamp when the environment was created"`
	// UpdatedAt is the timestamp when the environment was last updated.
	UpdatedAt *time.Time `json:"updated_at" jsonschema:"Timestamp when the environment was last updated"`
}

type ListEnvironmentsResponse struct {
	Data     []Environment `json:"data" jsonschema:"List of environments"`
	Metadata struct {
		Pagination PaginationMetadata `json:"pagination" jsonschema:"Pagination cursors for navigating results"`
	} `json:"metadata" jsonschema:"Response metadata including pagination"`
}

type CreateEnvironmentRequest struct {
	// Name is the environment display name (3-255 characters).
	Name string `json:"name"`
	// Description is the environment description (max 256 characters).
	Description string `json:"description,omitempty"`
	// LimitMode is the limit behavior mode. Values: "none", "restrict", "notify".
	LimitMode string `json:"limit_mode,omitempty"`
	// LimitValue is the threshold value. Required if LimitMode is not "none". Minimum: 1.
	LimitValue int `json:"limit_value,omitempty"`
}

type UpdateEnvironmentRequest struct {
	// Name is the environment display name (max 255 characters).
	Name *string `json:"name,omitempty"`
	// Description is the environment description (max 256 characters).
	Description *string `json:"description,omitempty"`
	// LimitMode is the limit behavior mode. Values: "none", "restrict", "notify".
	LimitMode *string `json:"limit_mode,omitempty"`
	// LimitValue is the threshold value. Required if LimitMode is not "none".
	LimitValue *int `json:"limit_value,omitempty"`
}

type environmentResponse struct {
	Data Environment `json:"data"`
}

func (c *Client) ListEnvironments(ctx context.Context, pagination *PaginationParams) (*ListEnvironmentsResponse, error) {
	q := url.Values{}
	addPaginationParams(q, pagination)

	req, err := c.newRequest(ctx, "GET", "/environments", q, nil)
	if err != nil {
		return nil, err
	}

	var resp ListEnvironmentsResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CreateEnvironment(ctx context.Context, input CreateEnvironmentRequest) (*Environment, error) {
	req, err := c.newRequest(ctx, "POST", "/environments", nil, input)
	if err != nil {
		return nil, err
	}

	var resp environmentResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateEnvironment(ctx context.Context, id string, input UpdateEnvironmentRequest) (*Environment, error) {
	req, err := c.newRequest(ctx, "POST", "/environments/"+id, nil, input)
	if err != nil {
		return nil, err
	}

	var resp environmentResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteEnvironment(ctx context.Context, id string) error {
	req, err := c.newRequest(ctx, "DELETE", "/environments/"+id, nil, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
