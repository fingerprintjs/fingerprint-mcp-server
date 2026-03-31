package fpmcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/mgmtapi"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (a *App) requireMgmtClient(req *mcp.CallToolRequest) (*mgmtapi.Client, error) {
	var apiKey string
	if a.cfg.PublicMode {
		apiKey = req.Extra.TokenInfo.Extra[tokenExtraMgmtApiKey].(string)
	} else {
		apiKey = a.cfg.ManagementAPIKey
	}
	if apiKey == "" {
		return nil, errors.New("management API key is required")
	}

	mgmtApiOpts := []mgmtapi.ClientOption{
		mgmtapi.WithApiKey(apiKey),
		mgmtapi.WithHTTPClient(&http.Client{
			Transport: &iiTransport{
				base:    http.DefaultTransport,
				version: a.version,
				appName: a.appName,
			},
		}),
	}
	if a.cfg.ManagementAPIURL != "" {
		mgmtApiOpts = append(mgmtApiOpts, mgmtapi.WithBaseURL(a.cfg.ManagementAPIURL))
	}
	return mgmtapi.NewClient(mgmtApiOpts...), nil
}

// --- Environment tool types ---

type ListEnvironmentsInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Pagination cursor for retrieving items after given position"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum items per page (0-101, default: 10)"`
}

type ListEnvironmentsOutput struct {
	Environments mgmtapi.ListEnvironmentsResponse `json:"environments" jsonschema:"Paginated list of environments with metadata containing pagination cursors"`
}

type CreateEnvironmentInput struct {
	Name        string `json:"name" jsonschema:"Environment display name (3-255 characters)"`
	Description string `json:"description,omitempty" jsonschema:"Environment description (max 256 characters)"`
	LimitMode   string `json:"limit_mode,omitempty" jsonschema:"Limit behavior mode. Values: none, restrict, notify"`
	LimitValue  int    `json:"limit_value,omitempty" jsonschema:"Threshold value. Required if limit_mode is not none. Minimum: 1"`
}

type CreateEnvironmentOutput struct {
	Environment mgmtapi.Environment `json:"environment" jsonschema:"The created environment with id, name, description, limit_mode, limit_value, is_restricted, restricted_at, created_at, and updated_at"`
}

type UpdateEnvironmentInput struct {
	ID          string  `json:"id" jsonschema:"Environment identifier"`
	Name        *string `json:"name,omitempty" jsonschema:"Environment display name (max 255 characters)"`
	Description *string `json:"description,omitempty" jsonschema:"Environment description (max 256 characters)"`
	LimitMode   *string `json:"limit_mode,omitempty" jsonschema:"Limit behavior mode. Values: none, restrict, notify"`
	LimitValue  *int    `json:"limit_value,omitempty" jsonschema:"Threshold value. Required if limit_mode is not none"`
}

type UpdateEnvironmentOutput struct {
	Environment mgmtapi.Environment `json:"environment" jsonschema:"The updated environment with id, name, description, limit_mode, limit_value, is_restricted, restricted_at, created_at, and updated_at"`
}

type DeleteEnvironmentInput struct {
	ID string `json:"id" jsonschema:"Environment identifier. You can only delete environments without active API keys"`
}

// --- API Key tool types ---

type ListAPIKeysInput struct {
	Type        string `json:"type,omitempty" jsonschema:"Filter by key type. Values: public, secret, proxy"`
	Status      string `json:"status,omitempty" jsonschema:"Filter by key status. Values: enabled, disabled"`
	Environment string `json:"environment,omitempty" jsonschema:"Filter by environment ID"`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Pagination cursor for retrieving items after given position"`
	Limit       int    `json:"limit,omitempty" jsonschema:"Maximum items per page (0-101, default: 10)"`
}

type ListAPIKeysOutput struct {
	APIKeys mgmtapi.ListAPIKeysResponse `json:"api_keys" jsonschema:"Paginated list of API keys with metadata containing pagination cursors"`
}

type GetAPIKeyInput struct {
	ID string `json:"id" jsonschema:"API key identifier"`
}

type GetAPIKeyOutput struct {
	APIKey mgmtapi.APIKey `json:"api_key" jsonschema:"The API key with id, name, description, status, environment, type, token, rate_limit, created_at, and disabled_at"`
}

type CreateAPIKeyInput struct {
	Type        string `json:"type" jsonschema:"API key type. Values: public, secret, proxy"`
	Name        string `json:"name" jsonschema:"API key display name (3-255 characters)"`
	Description string `json:"description,omitempty" jsonschema:"API key description (3-255 characters)"`
	Environment string `json:"environment,omitempty" jsonschema:"Environment ID. If omitted for proxy/secret keys, scopes to the workspace"`
}

type CreateAPIKeyOutput struct {
	APIKey mgmtapi.APIKey `json:"api_key" jsonschema:"The created API key with id, name, description, status, environment, type, token, rate_limit, created_at, and disabled_at. Secret key tokens are only visible at creation time"`
}

type UpdateAPIKeyInput struct {
	ID          string   `json:"id" jsonschema:"API key identifier"`
	Name        *string  `json:"name,omitempty" jsonschema:"API key display name (3-255 characters)"`
	Description *string  `json:"description,omitempty" jsonschema:"API key description (3-255 characters)"`
	Status      *string  `json:"status,omitempty" jsonschema:"Enable or disable the key. Values: enabled, disabled"`
	RateLimit   *float64 `json:"rate_limit,omitempty" jsonschema:"Requests-per-second limit. Minimum: 0.1"`
}

type UpdateAPIKeyOutput struct {
	APIKey mgmtapi.APIKey `json:"api_key" jsonschema:"The updated API key with id, name, description, status, environment, type, token, rate_limit, created_at, and disabled_at"`
}

type DeleteAPIKeyInput struct {
	ID string `json:"id" jsonschema:"API key identifier"`
}

// --- Environment management tools ---

func (a *App) registerListEnvironmentsTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "list_environments",
		Description: "Lists all workspace environments. Returns environment details including name, description, limits, and restriction status. For schema, see mcp resource fingerprint://schemas/environment",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "List Environments",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListEnvironmentsInput) (*mcp.CallToolResult, *ListEnvironmentsOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		var pagination *mgmtapi.PaginationParams
		if input.Cursor != "" || input.Limit > 0 {
			pagination = &mgmtapi.PaginationParams{Cursor: input.Cursor, Limit: input.Limit}
		}

		resp, err := mgmtClient.ListEnvironments(ctx, pagination)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list environments: %w", err)
		}

		return nil, &ListEnvironmentsOutput{Environments: *resp}, nil
	})

	return nil
}

func (a *App) registerCreateEnvironmentTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "create_environment",
		Description: "Creates a new workspace environment. Requires a name (3-255 chars). Optionally set description, limit mode (none/restrict/notify), and limit value. For schema, see mcp resource fingerprint://schemas/environment",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Create Environment",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CreateEnvironmentInput) (*mcp.CallToolResult, *CreateEnvironmentOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.Name == "" {
			return nil, nil, errors.New("name is required")
		}

		env, err := mgmtClient.CreateEnvironment(ctx, mgmtapi.CreateEnvironmentRequest{
			Name:        input.Name,
			Description: input.Description,
			LimitMode:   input.LimitMode,
			LimitValue:  input.LimitValue,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create environment: %w", err)
		}

		return nil, &CreateEnvironmentOutput{Environment: *env}, nil
	})

	return nil
}

func (a *App) registerUpdateEnvironmentTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "update_environment",
		Description: "Updates an existing workspace environment. Only provided fields are changed. For schema, see mcp resource fingerprint://schemas/environment",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Update Environment",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateEnvironmentInput) (*mcp.CallToolResult, *UpdateEnvironmentOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}

		env, err := mgmtClient.UpdateEnvironment(ctx, input.ID, mgmtapi.UpdateEnvironmentRequest{
			Name:        input.Name,
			Description: input.Description,
			LimitMode:   input.LimitMode,
			LimitValue:  input.LimitValue,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update environment: %w", err)
		}

		return nil, &UpdateEnvironmentOutput{Environment: *env}, nil
	})

	return nil
}

func (a *App) registerDeleteEnvironmentTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "delete_environment",
		Description: "Deletes a workspace environment. You can only delete environments that don't have any active API keys associated with them.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(true),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Delete Environment",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DeleteEnvironmentInput) (*mcp.CallToolResult, *struct{}, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}

		if err := mgmtClient.DeleteEnvironment(ctx, input.ID); err != nil {
			return nil, nil, fmt.Errorf("failed to delete environment: %w", err)
		}

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Environment deleted successfully"}}}, nil, nil
	})

	return nil
}

// --- API Key management tools ---

func (a *App) registerListAPIKeysTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "list_api_keys",
		Description: "Lists API keys with optional filters by type (public/secret/proxy), status (enabled/disabled), and environment. Supports pagination. For schema, see mcp resource fingerprint://schemas/api-key",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "List API Keys",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListAPIKeysInput) (*mcp.CallToolResult, *ListAPIKeysOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		var params *mgmtapi.ListAPIKeysParams
		if input.Type != "" || input.Status != "" || input.Environment != "" {
			params = &mgmtapi.ListAPIKeysParams{
				Type:        input.Type,
				Status:      input.Status,
				Environment: input.Environment,
			}
		}

		var pagination *mgmtapi.PaginationParams
		if input.Cursor != "" || input.Limit > 0 {
			pagination = &mgmtapi.PaginationParams{Cursor: input.Cursor, Limit: input.Limit}
		}

		resp, err := mgmtClient.ListAPIKeys(ctx, params, pagination)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list API keys: %w", err)
		}

		return nil, &ListAPIKeysOutput{APIKeys: *resp}, nil
	})

	return nil
}

func (a *App) registerGetAPIKeyTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "get_api_key",
		Description: "Retrieves detailed information about a specific API key by its ID. For schema, see mcp resource fingerprint://schemas/api-key",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "Get API Key",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GetAPIKeyInput) (*mcp.CallToolResult, *GetAPIKeyOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}

		key, err := mgmtClient.GetAPIKey(ctx, input.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get API key: %w", err)
		}

		return nil, &GetAPIKeyOutput{APIKey: *key}, nil
	})

	return nil
}

func (a *App) registerCreateAPIKeyTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "create_api_key",
		Description: "Creates a new API key. Requires type (public/secret/proxy) and name (3-255 chars). Secret key tokens are only visible at creation time. For schema, see mcp resource fingerprint://schemas/api-key",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Create API Key",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CreateAPIKeyInput) (*mcp.CallToolResult, *CreateAPIKeyOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.Type == "" {
			return nil, nil, errors.New("type is required")
		}
		if input.Name == "" {
			return nil, nil, errors.New("name is required")
		}

		key, err := mgmtClient.CreateAPIKey(ctx, mgmtapi.CreateAPIKeyRequest{
			Type:        input.Type,
			Name:        input.Name,
			Description: input.Description,
			Environment: input.Environment,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create API key: %w", err)
		}

		return nil, &CreateAPIKeyOutput{APIKey: *key}, nil
	})

	return nil
}

func (a *App) registerUpdateAPIKeyTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "update_api_key",
		Description: "Updates an existing API key. Can change name, description, status (enabled/disabled), and rate limit. Only provided fields are changed. For schema, see mcp resource fingerprint://schemas/api-key",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Update API Key",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateAPIKeyInput) (*mcp.CallToolResult, *UpdateAPIKeyOutput, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}

		key, err := mgmtClient.UpdateAPIKey(ctx, input.ID, mgmtapi.UpdateAPIKeyRequest{
			Name:        input.Name,
			Description: input.Description,
			Status:      input.Status,
			RateLimit:   input.RateLimit,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update API key: %w", err)
		}

		return nil, &UpdateAPIKeyOutput{APIKey: *key}, nil
	})

	return nil
}

func (a *App) registerDeleteAPIKeyTool(_ context.Context) error {
	mcp.AddTool(a.server, &mcp.Tool{
		Name:        "delete_api_key",
		Description: "Deletes an API key. This operation is irreversible.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(true),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Delete API Key",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DeleteAPIKeyInput) (*mcp.CallToolResult, *struct{}, error) {
		var mgmtClient *mgmtapi.Client
		var err error

		if mgmtClient, err = a.requireMgmtClient(req); err != nil {
			return nil, nil, err
		}

		if input.ID == "" {
			return nil, nil, errors.New("id is required")
		}

		if err := mgmtClient.DeleteAPIKey(ctx, input.ID); err != nil {
			return nil, nil, fmt.Errorf("failed to delete API key: %w", err)
		}

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "API key deleted successfully"}}}, nil, nil
	})

	return nil
}
