package mgmtapi

import (
	"context"
	"net/url"
	"time"
)

type FilteringRule struct {
	// ID is the auto-generated rule identifier.
	ID string `json:"id"`
	// Name is the rule name.
	Name string `json:"name"`
	// Environment is the associated environment ID.
	Environment string `json:"environment"`
	// Expression is the rule condition in expr-lang format.
	Expression string `json:"expression"`
	// Action is what happens when the rule matches. Values: "allow", "deny".
	Action string `json:"action"`
	// Status is the rule status. Values: "enabled", "disabled".
	Status string `json:"status"`
	// DenyWith is the custom error message returned for denied requests.
	DenyWith *string `json:"deny_with"`
	// CreatedAt is the timestamp when the rule was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the timestamp when the rule was last modified.
	UpdatedAt *time.Time `json:"updated_at"`
}

type ListFilteringRulesParams struct {
	// Environment filters by environment ID.
	Environment string
	// Status filters by rule status. Values: "enabled", "disabled".
	Status string
	// Name filters by rule name (partial match).
	Name string
}

type listFilteringRulesResponse struct {
	Data []FilteringRule `json:"data"`
}

type RulePlacement struct {
	// Position is the index to insert the rule at. Minimum: 0.
	Position *int `json:"position,omitempty"`
	// After is the ID of the rule to insert after.
	After string `json:"after,omitempty"`
	// Before is the ID of the rule to insert before.
	Before string `json:"before,omitempty"`
}

type CreateFilteringRuleRequest struct {
	// Name is the filtering rule name.
	Name string `json:"name"`
	// Environment is the environment ID.
	Environment string `json:"environment"`
	// Expression is the rule condition in expr-lang format.
	Expression string `json:"expression"`
	// Action is what happens when the rule matches. Values: "allow", "deny".
	Action string `json:"action"`
	// Status is the rule status. Values: "enabled", "disabled". Default: "enabled".
	Status string `json:"status,omitempty"`
	// DenyWith is the error message for denied requests. Values: "Forbidden".
	DenyWith string `json:"deny_with,omitempty"`
	// Placement controls the position of the rule in the evaluation order.
	Placement *RulePlacement `json:"placement,omitempty"`
}

type UpdateFilteringRuleRequest struct {
	// Name is the filtering rule name.
	Name *string `json:"name,omitempty"`
	// Environment is the environment ID.
	Environment *string `json:"environment,omitempty"`
	// Expression is the rule condition in expr-lang format.
	Expression *string `json:"expression,omitempty"`
	// Action is what happens when the rule matches. Values: "allow", "deny".
	Action *string `json:"action,omitempty"`
	// Status is the rule status. Values: "enabled", "disabled".
	Status *string `json:"status,omitempty"`
	// DenyWith is the error message for denied requests. Values: "Forbidden".
	DenyWith *string `json:"deny_with,omitempty"`
	// Placement controls the position of the rule in the evaluation order.
	Placement *RulePlacement `json:"placement,omitempty"`
}

type BulkFilteringRulesRequest struct {
	// Rules is the list of filtering rules to create or update.
	Rules []BulkFilteringRuleItem `json:"rules"`
	// Mode controls how existing rules are handled. Values: "merge" (default), "overwrite".
	Mode string `json:"mode,omitempty"`
	// Environment is the environment ID.
	Environment string `json:"environment"`
}

type BulkFilteringRuleItem struct {
	// Name is the filtering rule name.
	Name string `json:"name"`
	// Expression is the rule condition in expr-lang format.
	Expression string `json:"expression"`
	// Action is what happens when the rule matches. Values: "allow", "deny".
	Action string `json:"action"`
	// Status is the rule status. Values: "enabled", "disabled". Default: "enabled".
	Status string `json:"status,omitempty"`
	// DenyWith is the error message for denied requests. Values: "Forbidden".
	DenyWith string `json:"deny_with,omitempty"`
	// Placement controls the position of the rule in the evaluation order.
	Placement *RulePlacement `json:"placement,omitempty"`
}

type TestFilteringRulesRequest struct {
	// Rules is the list of custom rules to test. Omit to test existing rules for the environment.
	Rules []TestFilteringRule `json:"rules,omitempty"`
	// Environment is the environment ID. Required if Rules is omitted.
	Environment string `json:"environment,omitempty"`
	// TestRequestID is a historical request ID to evaluate against (up to 3 months old).
	TestRequestID string `json:"test_request_id,omitempty"`
	// TestRequestPayload is custom request data to evaluate rules against.
	TestRequestPayload *TestPayload `json:"test_request_payload,omitempty"`
}

type TestFilteringRule struct {
	// Expression is the rule condition in expr-lang format.
	Expression string `json:"expression"`
	// Action is what happens when the rule matches. Values: "allow", "deny".
	Action string `json:"action"`
	// DenyWith is the error message for denied requests. Values: "Forbidden".
	DenyWith string `json:"deny_with,omitempty"`
}

type TestPayload struct {
	// Headers is a map of HTTP header names to their values.
	Headers map[string][]string `json:"headers,omitempty"`
	// IP is the request IP address.
	IP string `json:"ip,omitempty"`
	// UserAgent is the request user agent string.
	UserAgent string `json:"userAgent,omitempty"`
	// SDKPlatform is the SDK platform. Values: "js", "android", "ios".
	SDKPlatform string `json:"sdkPlatform,omitempty"`
	// SDKVersion is the SDK version string.
	SDKVersion string `json:"sdkVersion,omitempty"`
	// AppPackageName is the application package name.
	AppPackageName string `json:"appPackageName,omitempty"`
}

type TestFilteringRulesResponse struct {
	// Result is the overall outcome. Values: "allow", "deny".
	Result string `json:"result"`
	// DenyWith is the error message if the result is "deny".
	DenyWith *string `json:"deny_with"`
	// TriggeredRule is the expression of the rule that matched.
	TriggeredRule *string `json:"triggered_rule"`
}

type filteringRuleResponse struct {
	Data FilteringRule `json:"data"`
}

type bulkFilteringRulesResponse struct {
	Data []FilteringRule `json:"data"`
}

func (c *Client) ListFilteringRules(ctx context.Context, params *ListFilteringRulesParams) ([]FilteringRule, error) {
	q := url.Values{}
	if params != nil {
		if params.Environment != "" {
			q.Set("environment", params.Environment)
		}
		if params.Status != "" {
			q.Set("status", params.Status)
		}
		if params.Name != "" {
			q.Set("name", params.Name)
		}
	}

	req, err := c.newRequest(ctx, "GET", "/filtering-rules", q, nil)
	if err != nil {
		return nil, err
	}

	var resp listFilteringRulesResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) GetFilteringRule(ctx context.Context, id string) (*FilteringRule, error) {
	req, err := c.newRequest(ctx, "GET", "/filtering-rules/"+id, nil, nil)
	if err != nil {
		return nil, err
	}

	var resp filteringRuleResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateFilteringRule(ctx context.Context, input CreateFilteringRuleRequest) (*FilteringRule, error) {
	req, err := c.newRequest(ctx, "POST", "/filtering-rules", nil, input)
	if err != nil {
		return nil, err
	}

	var resp filteringRuleResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateFilteringRule(ctx context.Context, id string, input UpdateFilteringRuleRequest) (*FilteringRule, error) {
	req, err := c.newRequest(ctx, "POST", "/filtering-rules/"+id, nil, input)
	if err != nil {
		return nil, err
	}

	var resp filteringRuleResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteFilteringRule(ctx context.Context, id string) error {
	req, err := c.newRequest(ctx, "DELETE", "/filtering-rules/"+id, nil, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) BulkFilteringRules(ctx context.Context, input BulkFilteringRulesRequest) ([]FilteringRule, error) {
	req, err := c.newRequest(ctx, "POST", "/filtering-rules/bulk", nil, input)
	if err != nil {
		return nil, err
	}

	var resp bulkFilteringRulesResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) TestFilteringRules(ctx context.Context, input TestFilteringRulesRequest) (*TestFilteringRulesResponse, error) {
	req, err := c.newRequest(ctx, "POST", "/filtering-rules/test", nil, input)
	if err != nil {
		return nil, err
	}

	var resp TestFilteringRulesResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
