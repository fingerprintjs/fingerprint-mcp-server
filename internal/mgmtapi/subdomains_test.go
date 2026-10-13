package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const testSubdomain = `{"id":"certv2_test","subdomain":"metrics.example.com","status":"pending","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z","dns_records":{"verification":{"type":"CNAME","host":"_acme-challenge.metrics.example.com","value":"validation.example.com","status":"validated"},"routing":[{"type":"A","host":"metrics.example.com","value":"162.159.141.170","status":"pending_validation"},{"type":"A","host":"metrics.example.com","value":"172.66.1.166","status":"pending_validation"}],"caa":{"type":"CAA","host":"metrics.example.com","value":"0 issue pki.goog","status":"failed"}}}`

func TestSubdomainOperations(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer test-key" || r.Header.Get("X-API-Version") != apiVersionValue {
			t.Error("missing authentication or API version")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subdomains":
			fmt.Fprintf(w, `{"data":[%s],"metadata":{"pagination":{"next_cursor":"next-page","prev_cursor":null}}}`, testSubdomain)
		case r.Method == http.MethodPost && r.URL.Path == "/subdomains":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"subdomain":"metrics.example.com"}` {
				t.Errorf("unexpected create body: %s", body)
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"data":%s}`, testSubdomain)
		case strings.HasSuffix(r.URL.Path, "/verify"):
			// The POST representation can be stale; only the following GET is returned.
			fmt.Fprint(w, `{"data":{"status":"failed"}}`)
		default:
			fmt.Fprintf(w, `{"data":%s}`, testSubdomain)
		}
	}))
	defer server.Close()
	client := NewClient(WithBaseURL(server.URL), WithApiKey("test-key"))
	ctx := context.Background()

	page, err := client.ListSubdomains(ctx, &PaginationParams{Cursor: "a+b", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 1 || page.Data[0].ID != "certv2_test" || page.Metadata.Pagination.NextCursor == nil || *page.Metadata.Pagination.NextCursor != "next-page" {
		t.Fatalf("unexpected page: %+v", page)
	}
	for _, call := range []func() (*Subdomain, error){
		func() (*Subdomain, error) { return client.CreateSubdomain(ctx, "metrics.example.com") },
		func() (*Subdomain, error) { return client.GetSubdomain(ctx, "certv2_test") },
		func() (*Subdomain, error) { return client.VerifySubdomain(ctx, "certv2_test") },
	} {
		subdomain, err := call()
		if err != nil {
			t.Fatal(err)
		}
		if subdomain.Status != "pending" || subdomain.DNSRecords.Verification.Status != "validated" || len(subdomain.DNSRecords.Routing) != 2 || subdomain.DNSRecords.CAA == nil || subdomain.DNSRecords.CAA.Status != "failed" {
			t.Fatalf("incomplete subdomain: %+v", subdomain)
		}
	}
	want := []string{"GET /subdomains?cursor=a%2Bb&limit=2", "POST /subdomains", "GET /subdomains/certv2_test", "POST /subdomains/certv2_test/verify", "GET /subdomains/certv2_test"}
	if !reflect.DeepEqual(requests, want) {
		t.Errorf("requests = %v, want %v", requests, want)
	}
}

func TestSubdomainStatusesAndOptionalCAA(t *testing.T) {
	for _, status := range []string{"pending", "active", "timed_out", "failed"} {
		t.Run(status, func(t *testing.T) {
			var subdomain Subdomain
			if err := json.Unmarshal([]byte(`{"status":"`+status+`","dns_records":{"routing":[]}}`), &subdomain); err != nil {
				t.Fatal(err)
			}
			if subdomain.Status != status || subdomain.DNSRecords.CAA != nil {
				t.Fatalf("unexpected subdomain: %+v", subdomain)
			}
			body, err := json.Marshal(subdomain)
			if err != nil || strings.Contains(string(body), `"caa"`) {
				t.Fatalf("absent CAA must remain absent: %s (%v)", body, err)
			}
		})
	}
}

func TestVerifySubdomainDoesNotReadOrRetryAfterError(t *testing.T) {
	for _, status := range []int{400, 401, 404, 409, 422, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"message":"Request refused","code":"subdomains.error","violations":[{"property":"subdomain","message":"Invalid hostname"}]}}`)
			}))
			defer server.Close()
			client := NewClient(WithBaseURL(server.URL))
			_, err := client.VerifySubdomain(context.Background(), "certv2_test")
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status || apiErr.Code != "subdomains.error" || apiErr.RetryAfter != "60" || len(apiErr.Violations) != 1 {
				t.Fatalf("lost API error details: %+v", err)
			}
			if calls != 1 {
				t.Errorf("made %d requests, want one", calls)
			}
		})
	}
}

func TestManagementAPIErrorsRedactCredential(t *testing.T) {
	for _, body := range []string{
		`{"error":{"message":"Bearer secret-key","code":"secret-key","violations":[{"property":"secret-key","message":"secret-key"}]}}`,
		`upstream error: Bearer secret-key`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "secret-key")
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, body)
		}))
		client := NewClient(WithBaseURL(server.URL), WithApiKey("secret-key"))
		_, err := client.CreateSubdomain(context.Background(), "metrics.example.com")
		server.Close()
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected APIError: %v", err)
		}
		encoded, marshalErr := json.Marshal(apiErr)
		if marshalErr != nil || strings.Contains(string(encoded), "secret-key") || strings.Contains(err.Error(), "secret-key") {
			t.Fatalf("credential exposed: %s (%v)", encoded, marshalErr)
		}
	}
}
