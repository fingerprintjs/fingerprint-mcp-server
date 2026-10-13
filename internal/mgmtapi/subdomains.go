package mgmtapi

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type SubdomainListItem struct {
	ID        string    `json:"id" jsonschema:"Subdomain identifier"`
	Subdomain string    `json:"subdomain" jsonschema:"Subdomain hostname"`
	Status    string    `json:"status" jsonschema:"pending, active, timed_out or failed. Only active is ready to use"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SubdomainDNSRecord struct {
	Type   string `json:"type"`
	Host   string `json:"host"`
	Value  string `json:"value"`
	Status string `json:"status" jsonschema:"pending_validation, validated or failed"`
}

type SubdomainDNSRecords struct {
	Verification SubdomainDNSRecord   `json:"verification" jsonschema:"Ownership verification CNAME"`
	Routing      []SubdomainDNSRecord `json:"routing" jsonschema:"Routing A records"`
	CAA          *SubdomainDNSRecord  `json:"caa,omitempty" jsonschema:"CAA record when required for certificate issuance"`
}

type Subdomain struct {
	SubdomainListItem
	DNSRecords SubdomainDNSRecords `json:"dns_records"`
}

type ListSubdomainsResponse struct {
	Data     []SubdomainListItem `json:"data"`
	Metadata struct {
		Pagination PaginationMetadata `json:"pagination"`
	} `json:"metadata"`
}

type subdomainResponse struct {
	Data Subdomain `json:"data"`
}

func (c *Client) ListSubdomains(ctx context.Context, pagination *PaginationParams) (*ListSubdomainsResponse, error) {
	q := url.Values{}
	addPaginationParams(q, pagination)
	req, err := c.newRequest(ctx, http.MethodGet, "/subdomains", q, nil)
	if err != nil {
		return nil, err
	}
	var resp ListSubdomainsResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetSubdomain(ctx context.Context, id string) (*Subdomain, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/subdomains/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return nil, err
	}
	var resp subdomainResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateSubdomain(ctx context.Context, hostname string) (*Subdomain, error) {
	req, err := c.newRequest(ctx, http.MethodPost, "/subdomains", nil, struct {
		Subdomain string `json:"subdomain"`
	}{Subdomain: hostname})
	if err != nil {
		return nil, err
	}
	var resp subdomainResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) VerifySubdomain(ctx context.Context, id string) (*Subdomain, error) {
	req, err := c.newRequest(ctx, http.MethodPost, "/subdomains/"+url.PathEscape(id)+"/verify", nil, nil)
	if err != nil {
		return nil, err
	}
	// The check runs synchronously and the response already carries the updated subdomain.
	var resp subdomainResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

type DomainConnectLink struct {
	DomainConnectURL string `json:"domain_connect_url" jsonschema:"Signed link to the DNS provider; it redirects to the subdomain page in the Fingerprint dashboard once the records are added"`
	DNSProvider      string `json:"dns_provider,omitempty" jsonschema:"DNS provider display name when known, e.g. Cloudflare"`
}

type domainConnectResponse struct {
	Data DomainConnectLink `json:"data"`
}

// CreateDomainConnectURL asks for a Domain Connect link without a local callback port, so the
// provider redirects to the dashboard instead of a loopback listener this server cannot run.
func (c *Client) CreateDomainConnectURL(ctx context.Context, id string) (*DomainConnectLink, error) {
	req, err := c.newRequest(ctx, http.MethodPost, "/subdomains/"+url.PathEscape(id)+"/domain-connect", nil, struct{}{})
	if err != nil {
		return nil, err
	}
	var resp domainConnectResponse
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
