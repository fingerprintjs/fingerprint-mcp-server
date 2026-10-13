package fpmcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/mgmtapi"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/utils"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListSubdomainsInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Pagination cursor from the previous response"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum items per page; omit for the API default"`
}

type ListSubdomainsOutput struct {
	Subdomains mgmtapi.ListSubdomainsResponse `json:"subdomains" jsonschema:"Subdomains and pagination metadata; use get_subdomain for DNS records"`
}

// A subdomain is named by its id or, like in the CLI, by its hostname. The
// hostname is resolved through the list, so the id is the cheaper of the two.
type SubdomainRef struct {
	ID       string `json:"id,omitempty" jsonschema:"Subdomain id from list_subdomains or create_subdomain"`
	Hostname string `json:"hostname,omitempty" jsonschema:"Subdomain hostname, e.g. metrics.example.com, when the id is not at hand"`
}

type GetSubdomainInput = SubdomainRef

type CreateSubdomainInput struct {
	Hostname string `json:"hostname" jsonschema:"Exact user-approved subdomain, e.g. metrics.example.com. Not the apex or an existing website hostname"`
}

type VerifySubdomainInput = SubdomainRef

type ConnectSubdomainInput = SubdomainRef

type ConnectSubdomainOutput struct {
	Link mgmtapi.DomainConnectLink `json:"link" jsonschema:"Open domain_connect_url in the user's browser; after approving at the provider they land on the Fingerprint dashboard. Then verify_subdomain once"`
}

type SubdomainOutput struct {
	Subdomain mgmtapi.Subdomain `json:"subdomain" jsonschema:"Current status and all DNS records. Configure the app only when status is active"`
}

// resolveSubdomainID turns a hostname into the id the API wants, by walking
// the workspace's list. Matching is by normalized hostname, as in the CLI.
func resolveSubdomainID(ctx context.Context, client *mgmtapi.Client, ref SubdomainRef) (string, error) {
	if ref.ID != "" {
		return ref.ID, nil
	}
	hostname := normalizeHostname(ref.Hostname)
	if hostname == "" {
		return "", errors.New("id or hostname is required")
	}
	var matches []string
	// Same guard as the CLI's list: a cursor that comes back twice would otherwise loop forever.
	seen := map[string]bool{}
	pagination := &mgmtapi.PaginationParams{}
	for {
		page, err := client.ListSubdomains(ctx, pagination)
		if err != nil {
			return "", err
		}
		for _, item := range page.Data {
			if normalizeHostname(item.Subdomain) == hostname {
				matches = append(matches, item.ID)
			}
		}
		next := page.Metadata.Pagination.NextCursor
		if next == nil || *next == "" {
			break
		}
		if seen[*next] {
			return "", errors.New("the Management API returned a repeated subdomain pagination cursor")
		}
		seen[*next] = true
		pagination = &mgmtapi.PaginationParams{Cursor: *next}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no custom subdomain named %s in this workspace: check list_subdomains", hostname)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("several subdomains match %s, pass one of their ids instead: %s", hostname, strings.Join(matches, ", "))
	}
}

func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
}

// verifyToolError adds what only verification knows: the API does not send Retry-After yet, and
// verification allows about one check per minute per subdomain, so a 429 gets that wait instead
// of nothing. Other subdomain calls keep the API's own 429 as is.
func verifyToolError(err error) (*mcp.CallToolResult, error) {
	var apiErr *mgmtapi.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests {
		limited := *apiErr
		if limited.RetryAfter == "" {
			limited.RetryAfter = "60"
		}
		limited.Message += ". Wait before the next verification; use get_subdomain for the current status."
		err = &limited
	}
	return subdomainToolError(err)
}

func subdomainToolError(err error) (*mcp.CallToolResult, error) {
	var apiErr *mgmtapi.APIError
	if !errors.As(err, &apiErr) {
		return nil, err
	}
	details := *apiErr
	switch details.StatusCode {
	case http.StatusUnauthorized:
		details.Message += ". Check the Management API key, or reconnect the Fingerprint connector."
	case http.StatusServiceUnavailable:
		details.Message = "Custom subdomain service is unavailable. It may be temporarily unavailable or disabled for this workspace; check with Fingerprint support before retrying."
	}
	body, err := json.Marshal(struct {
		Error mgmtapi.APIError `json:"error"`
	}{Error: details})
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}, nil
}

func (a *App) registerListSubdomainsTool(_ context.Context) error {
	addTool(a, &mcp.Tool{
		Name:        "list_subdomains",
		Description: "Lists workspace custom subdomains with pagination. Look for the user's hostname before creating one. Use get_subdomain for DNS records.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "List Subdomains",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListSubdomainsInput) (*mcp.CallToolResult, *ListSubdomainsOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		resp, err := client.ListSubdomains(ctx, &mgmtapi.PaginationParams{Cursor: input.Cursor, Limit: input.Limit})
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		return nil, &ListSubdomainsOutput{Subdomains: *resp}, nil
	})
	return nil
}

func (a *App) registerGetSubdomainTool(_ context.Context) error {
	addTool(a, &mcp.Tool{
		Name:        "get_subdomain",
		Description: "Gets a custom subdomain, by id or hostname: current status and DNS records without triggering verification. Only active means the app can use it; pending is not a failure.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    true,
			Title:           "Get Subdomain",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input GetSubdomainInput) (*mcp.CallToolResult, *SubdomainOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		id, err := resolveSubdomainID(ctx, client, input)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		subdomain, err := client.GetSubdomain(ctx, id)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		return nil, &SubdomainOutput{Subdomain: *subdomain}, nil
	})
	return nil
}

func (a *App) registerCreateSubdomainTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "create_subdomain",
		Description: "Registers the user-approved hostname and returns all required DNS records. Check list_subdomains first to reuse an existing resource. Add records manually or with an authorized DNS-provider tool (DNS only on Cloudflare). Do not configure the app until status is active.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Create Subdomain",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CreateSubdomainInput) (*mcp.CallToolResult, *SubdomainOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		if input.Hostname == "" {
			return nil, nil, errors.New("hostname is required")
		}
		subdomain, err := client.CreateSubdomain(ctx, input.Hostname)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		return nil, &SubdomainOutput{Subdomain: *subdomain}, nil
	})
	return nil
}

func (a *App) registerVerifySubdomainTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "verify_subdomain",
		Description: "Requests one DNS check for a subdomain, by id or hostname, after records are added or corrected, then reads the fresh subdomain status. Rate-limited: respect retry_after on 429. Use get_subdomain for subsequent status checks, not a verify loop. Only active permits configuring the app.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  false,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Verify Subdomain",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input VerifySubdomainInput) (*mcp.CallToolResult, *SubdomainOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		id, err := resolveSubdomainID(ctx, client, input)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		subdomain, err := client.VerifySubdomain(ctx, id)
		if err != nil {
			result, err := verifyToolError(err)
			return result, nil, err
		}
		return nil, &SubdomainOutput{Subdomain: *subdomain}, nil
	})
	return nil
}

func (a *App) registerConnectSubdomainTool(_ context.Context) error {
	addWriteTool(a, &mcp.Tool{
		Name:        "connect_subdomain",
		Description: "Returns a Domain Connect link that adds the DNS records at the user's DNS provider with one approval, for a pending subdomain by id or hostname. Ask the user to open it in their browser; after approving they land on the Fingerprint dashboard, which confirms the result. Then verify_subdomain once and get_subdomain for status. Returns a 409 error when the provider has no Domain Connect or the subdomain is no longer pending: show the DNS records instead.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: utils.Ptr(false),
			IdempotentHint:  true,
			OpenWorldHint:   utils.Ptr(false),
			ReadOnlyHint:    false,
			Title:           "Connect Subdomain (Domain Connect)",
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ConnectSubdomainInput) (*mcp.CallToolResult, *ConnectSubdomainOutput, error) {
		client, err := a.requireMgmtClient(req)
		if err != nil {
			return nil, nil, err
		}
		id, err := resolveSubdomainID(ctx, client, input)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		link, err := client.CreateDomainConnectURL(ctx, id)
		if err != nil {
			result, err := subdomainToolError(err)
			return result, nil, err
		}
		return nil, &ConnectSubdomainOutput{Link: *link}, nil
	})
	return nil
}
