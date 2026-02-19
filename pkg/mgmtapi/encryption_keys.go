package mgmtapi

import (
	"context"
	"net/url"
	"time"
)

type EncryptionKey struct {
	// ID is the auto-generated encryption key identifier.
	ID string `json:"id"`
	// Name is the encryption key name.
	Name string `json:"name"`
	// Description is the encryption key description.
	Description string `json:"description"`
	// Status is the encryption key status. Values: "enabled", "disabled".
	Status string `json:"status"`
	// Environment is the associated environment ID. Null if scoped to the workspace.
	Environment any `json:"environment"`
	// PreviousToken is the prior key value after rotation.
	PreviousToken string `json:"previous_token"`
	// Token is the current encryption key value.
	Token string `json:"token"`
	// NextToken is the upcoming key value.
	NextToken string `json:"next_token"`
	// CreatedAt is the timestamp when the encryption key was created.
	CreatedAt time.Time `json:"created_at"`
	// LastActivatedAt is the timestamp when the key was last activated.
	LastActivatedAt *time.Time `json:"last_activated_at"`
	// LastRotatedAt is the timestamp when the key was last rotated.
	LastRotatedAt *time.Time `json:"last_rotated_at"`
	// LastDeactivatedAt is the timestamp when the key was last deactivated.
	LastDeactivatedAt *time.Time `json:"last_deactivated_at"`
}

type ListEncryptionKeysParams struct {
	// Status filters by encryption key status. Values: "enabled", "disabled".
	Status string
	// Environment filters by environment ID.
	Environment string
}

type ListEncryptionKeysResponse struct {
	Data     []EncryptionKey `json:"data"`
	Metadata struct {
		Pagination PaginationMetadata `json:"pagination"`
	} `json:"metadata"`
}

type UpdateEncryptionKeyRequest struct {
	// Name sets the encryption key name.
	Name *string `json:"name,omitempty"`
	// Description sets the encryption key description.
	Description *string `json:"description,omitempty"`
	// Status enables or disables the encryption key. Values: "enabled", "disabled".
	Status *string `json:"status,omitempty"`
}

type encryptionKeyResponse struct {
	Data EncryptionKey `json:"data"`
}

func (c *Client) ListEncryptionKeys(ctx context.Context, params *ListEncryptionKeysParams, pagination *PaginationParams) (*ListEncryptionKeysResponse, error) {
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

	req, err := c.newRequest(ctx, "GET", "/encryption-keys", q, nil)
	if err != nil {
		return nil, err
	}

	var resp ListEncryptionKeysResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetEncryptionKey(ctx context.Context, id string) (*EncryptionKey, error) {
	req, err := c.newRequest(ctx, "GET", "/encryption-keys/"+id, nil, nil)
	if err != nil {
		return nil, err
	}

	var resp encryptionKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateEncryptionKey(ctx context.Context, id string, input UpdateEncryptionKeyRequest) (*EncryptionKey, error) {
	req, err := c.newRequest(ctx, "PATCH", "/encryption-keys/"+id, nil, input)
	if err != nil {
		return nil, err
	}

	var resp encryptionKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) RotateEncryptionKey(ctx context.Context, id string) (*EncryptionKey, error) {
	req, err := c.newRequest(ctx, "POST", "/encryption-keys/"+id+"/rotate", nil, nil)
	if err != nil {
		return nil, err
	}

	var resp encryptionKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) RevertEncryptionKey(ctx context.Context, id string) (*EncryptionKey, error) {
	req, err := c.newRequest(ctx, "POST", "/encryption-keys/"+id+"/revert", nil, nil)
	if err != nil {
		return nil, err
	}

	var resp encryptionKeyResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
