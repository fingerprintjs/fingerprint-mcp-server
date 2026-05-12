package fpmcpserver

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/analytics"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// analyticsResourceURI redacts per-call identifiers from templated MCP
// resource URIs before they're sent to long-retention analytics. Today the
// only templated URI is `fingerprint://events/{event_id}`; static URIs
// (e.g. `fingerprint://schemas/event`) pass through unchanged.
func analyticsResourceURI(uri string) string {
	const eventsPrefix = "fingerprint://events/"
	if len(uri) > len(eventsPrefix) && strings.HasPrefix(uri, eventsPrefix) {
		return eventsPrefix + "{event_id}"
	}
	return uri
}

// analyticsInputs bundles the values emitAnalytics needs from the
// middleware so the call site stays a single line.
type analyticsInputs struct {
	req      mcp.Request
	method   string
	subID    string
	clientIP string

	toolName, resourceURI, promptName string
	clientName, clientVersion         string

	duration     time.Duration
	isError      bool
	err          error
	errorClass   string
	errorMessage string
	result       mcp.Result
}

// emitAnalytics builds an mcp_method_called event and hands it to the
// configured emitter. Skipped when no subscription_id is available, which
// covers pre-auth methods, the private/preconfigured-key auth path, and
// any public-mode JWT that didn't carry the subscription claim. The
// default emitter is a no-op, so embedders that don't pass WithAnalytics
// pay nothing regardless.
//
// String-property capping (for wire-format limits) is the responsibility
// of the concrete emitter implementation, not this function.
func (a *App) emitAnalytics(in analyticsInputs) {
	if in.subID == "" {
		return
	}

	props := map[string]any{
		"method":         in.method,
		"duration_ms":    in.duration.Milliseconds(),
		"is_error":       in.isError || in.err != nil,
		"server_version": a.version,
		"transport":      a.cfg.Transport,
	}
	if in.toolName != "" {
		props["tool_name"] = in.toolName
	}
	if in.resourceURI != "" {
		props["resource_uri"] = analyticsResourceURI(in.resourceURI)
	}
	if in.promptName != "" {
		props["prompt_name"] = in.promptName
	}
	if in.errorClass != "" {
		props["error_class"] = in.errorClass
	}
	// Raw tool/prompt arguments. Extracted only inside the gate so private
	// mode and pre-auth methods don't pay the json.RawMessage->string copy
	// (tools/call) or fresh json.Marshal (prompts/get) on the silent path.
	var argumentsJSON string
	switch r := in.req.(type) {
	case *mcp.CallToolRequest:
		if len(r.Params.Arguments) > 0 {
			argumentsJSON = string(r.Params.Arguments)
		}
	case *mcp.GetPromptRequest:
		if len(r.Params.Arguments) > 0 {
			if b, mErr := json.Marshal(r.Params.Arguments); mErr == nil {
				argumentsJSON = string(b)
			}
		}
	}
	if argumentsJSON != "" {
		props["arguments"] = argumentsJSON
	}
	if in.errorMessage != "" {
		props["error_message"] = in.errorMessage
	}
	// result_size_bytes is the JSON-marshalled size of the successful
	// result payload, useful for spotting bloated responses without
	// shipping the content itself. Computed inside the gate so the
	// marshal cost is only paid when telemetry is actually enabled.
	// Errored calls don't return a meaningful result body.
	if in.err == nil && in.result != nil {
		if b, mErr := json.Marshal(in.result); mErr == nil {
			props["result_size_bytes"] = int64(len(b))
		}
	}
	// client_name/client_version ride only on the initialize event;
	// backends that support UserProperties stick them on the subscription
	// so later events inherit them at query time.
	var userProps map[string]any
	if in.clientName != "" {
		userProps = map[string]any{
			"client_name":    in.clientName,
			"client_version": in.clientVersion,
		}
	}
	a.opts.analyticsEmitter().Emit(analytics.Event{
		Type:           "mcp_method_called",
		SubscriptionID: in.subID,
		Properties:     props,
		UserProperties: userProps,
		IP:             in.clientIP,
	})
}
