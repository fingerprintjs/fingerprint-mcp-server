//go:generate go run -C ../.. ./cmd/generate-schema

package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/fingerprintjs/go-sdk/v8"
	"github.com/google/jsonschema-go/jsonschema"
)

// SchemaFromStruct generates a JSON Schema from a struct using reflection.
// Fields with `ref` tag use $ref to OpenAPI definitions.
// Fields with `description` tag get that description.
// The json tag determines property names; omitempty means not required.
func SchemaFromStruct(v any) json.RawMessage {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic("SchemaFromStruct requires a struct type")
	}

	var defs map[string]any
	if err := json.Unmarshal(openAPIDefs, &defs); err != nil {
		panic(fmt.Sprintf("failed to unmarshal openAPIDefs: %v", err))
	}

	properties := make(map[string]any)
	var required []string

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Get JSON property name
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}
		parts := strings.Split(jsonTag, ",")
		propName := parts[0]
		omitempty := len(parts) > 1 && parts[1] == "omitempty"

		// Build property schema
		propSchema := make(map[string]any)

		if ref := field.Tag.Get("ref"); ref != "" {
			// Use $ref to OpenAPI definition
			propSchema["$ref"] = "#/$defs/" + ref
		} else {
			// Infer type from Go type
			propSchema["type"] = goTypeToJSONSchemaType(field.Type)
		}

		if desc := field.Tag.Get("jsonschema"); desc != "" {
			propSchema["description"] = desc
		}

		properties[propName] = propSchema

		if !omitempty {
			required = append(required, propName)
		}
	}

	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
		"$defs":                defs,
	}
	if len(required) > 0 {
		schema["required"] = required
	}

	b, err := json.Marshal(schema)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal schema: %v", err))
	}
	return b
}

// PatchProductsEnum injects an "items.enum" constraint into the "products" property
// of the given JSON Schema. It returns the patched schema.
func PatchProductsEnum(schema json.RawMessage) json.RawMessage {
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		panic(fmt.Sprintf("PatchProductsEnum: unmarshal: %v", err))
	}

	var fields []any
	if err := json.Unmarshal(productsFields, &fields); err != nil {
		panic(fmt.Sprintf("PatchProductsEnum: unmarshal productsFields: %v", err))
	}

	props, ok := s["properties"].(map[string]any)
	if !ok {
		return schema
	}

	props["products"] = map[string]any{
		"type":        "array",
		"description": "Optional list of product fields to include in the response. If omitted all products are returned.",
		"items": map[string]any{
			"type": "string",
			"enum": fields,
		},
	}

	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("PatchProductsEnum: marshal: %v", err))
	}
	return b
}

// productFieldNames returns the set of JSON field names that are considered
// "product" fields on the Event struct, loaded from the embedded productsFields JSON.
func productFieldNames() map[string]bool {
	var fields []string
	if err := json.Unmarshal(productsFields, &fields); err != nil {
		panic(fmt.Sprintf("productFieldNames: unmarshal: %v", err))
	}
	m := make(map[string]bool, len(fields))
	for _, f := range fields {
		m[f] = true
	}
	return m
}

// StripAdditionalProperties nils out the AdditionalProperties map on the given
// struct (and any nested structs) so that serialized JSON won't contain extra
// keys that violate "additionalProperties: false" in the schema.
func StripAdditionalProperties(v any) {
	stripAdditionalProperties(reflect.ValueOf(v))
}

func stripAdditionalProperties(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			stripAdditionalProperties(v.Elem())
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := v.Field(i)
			if t.Field(i).Name == "AdditionalProperties" && f.Kind() == reflect.Map {
				f.Set(reflect.Zero(f.Type()))
				continue
			}
			stripAdditionalProperties(f)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			stripAdditionalProperties(v.Index(i))
		}
	}
}

// FilterProducts nils out product-related fields on the Event struct that are not
// in the requested set. Non-product metadata fields (event_id, timestamp, etc.)
// are never touched. Since product fields are pointers tagged with omitempty,
// nilled fields are omitted from the JSON output automatically.
func FilterProducts(event *fingerprint.Event, fields []string) {
	if event == nil || len(fields) == 0 {
		return
	}

	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}

	productFields := productFieldNames()

	v := reflect.ValueOf(event).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		jsonName := strings.SplitN(t.Field(i).Tag.Get("json"), ",", 2)[0]
		if !productFields[jsonName] {
			continue // not a product field, skip
		}
		if !allowed[jsonName] {
			v.Field(i).Set(reflect.Zero(t.Field(i).Type))
		}
	}
}

func goTypeToJSONSchemaType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "string"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	default:
		return "object"
	}
}

// SearchEventInputToRequest converts a SearchEventInput into a fingerprint.SearchEventRequest.
// Returns an error if start/end are not valid RFC3339.
func SearchEventInputToRequest(input *SearchEventInput) (fingerprint.SearchEventRequest, error) {
	req := fingerprint.NewSearchEventsRequest()
	if input.Limit != nil {
		req = req.Limit(*input.Limit)
	}
	if input.PaginationKey != nil {
		req = req.PaginationKey(*input.PaginationKey)
	}
	if input.VisitorId != nil {
		req = req.VisitorID(*input.VisitorId)
	}
	if s, ok := input.Bot.(string); ok {
		req = req.Bot(fingerprint.SearchEventsBot(s))
	}
	if input.IpAddress != nil {
		req = req.IPAddress(*input.IpAddress)
	}
	if input.Asn != nil {
		req = req.Asn(*input.Asn)
	}
	if input.LinkedId != nil {
		req = req.LinkedID(*input.LinkedId)
	}
	if input.Url != nil {
		req = req.URL(*input.Url)
	}
	if input.BundleId != nil {
		req = req.BundleID(*input.BundleId)
	}
	if input.PackageName != nil {
		req = req.PackageName(*input.PackageName)
	}
	if input.Origin != nil {
		req = req.Origin(*input.Origin)
	}
	if input.Start != nil {
		t, err := time.Parse(time.RFC3339Nano, *input.Start)
		if err != nil {
			return req, fmt.Errorf(`invalid "start": must be an RFC3339 timestamp like "YYYY-MM-DDTHH:MM:SSZ" (got %q)`, *input.Start)
		}
		req = req.Start(t.UnixMilli())
	}
	if input.End != nil {
		t, err := time.Parse(time.RFC3339Nano, *input.End)
		if err != nil {
			return req, fmt.Errorf(`invalid "end": must be an RFC3339 timestamp like "YYYY-MM-DDTHH:MM:SSZ" (got %q)`, *input.End)
		}
		req = req.End(t.UnixMilli())
	}
	if input.Reverse != nil {
		req = req.Reverse(*input.Reverse)
	}
	if input.Suspect != nil {
		req = req.Suspect(*input.Suspect)
	}
	if input.Vpn != nil {
		req = req.VPN(*input.Vpn)
	}
	if input.VirtualMachine != nil {
		req = req.VirtualMachine(*input.VirtualMachine)
	}
	if input.Tampering != nil {
		req = req.Tampering(*input.Tampering)
	}
	if input.AntiDetectBrowser != nil {
		req = req.AntiDetectBrowser(*input.AntiDetectBrowser)
	}
	if input.Incognito != nil {
		req = req.Incognito(*input.Incognito)
	}
	if input.PrivacySettings != nil {
		req = req.PrivacySettings(*input.PrivacySettings)
	}
	if input.Jailbroken != nil {
		req = req.Jailbroken(*input.Jailbroken)
	}
	if input.Frida != nil {
		req = req.Frida(*input.Frida)
	}
	if input.FactoryReset != nil {
		req = req.FactoryReset(*input.FactoryReset)
	}
	if input.ClonedApp != nil {
		req = req.ClonedApp(*input.ClonedApp)
	}
	if input.Emulator != nil {
		req = req.Emulator(*input.Emulator)
	}
	if input.RootApps != nil {
		req = req.RootApps(*input.RootApps)
	}
	if s, ok := input.VpnConfidence.(string); ok {
		req = req.VPNConfidence(fingerprint.SearchEventsVPNConfidence(s))
	}
	if input.MinSuspectScore != nil {
		req = req.MinSuspectScore(*input.MinSuspectScore)
	}
	if input.DeveloperTools != nil {
		req = req.DeveloperTools(*input.DeveloperTools)
	}
	if input.LocationSpoofing != nil {
		req = req.LocationSpoofing(*input.LocationSpoofing)
	}
	if input.MitmAttack != nil {
		req = req.MITMAttack(*input.MitmAttack)
	}
	if input.Proxy != nil {
		req = req.Proxy(*input.Proxy)
	}
	if input.SdkVersion != nil {
		req = req.SDKVersion(*input.SdkVersion)
	}
	if s, ok := input.SdkPlatform.(string); ok {
		req = req.SDKPlatform(fingerprint.SearchEventsSDKPlatform(s))
	}
	if len(input.Environment) > 0 {
		req = req.Environment(input.Environment)
	}
	if input.ProximityId != nil {
		req = req.ProximityID(*input.ProximityId)
	}
	if input.TotalHits != nil {
		req = req.TotalHits(*input.TotalHits)
	}
	if input.TorNode != nil {
		req = req.TorNode(*input.TorNode)
	}
	return req, nil
}

func MustInferSchema[T any]() json.RawMessage {
	s, err := jsonschema.For[T](&jsonschema.ForOptions{IgnoreInvalidTypes: true})
	if err != nil {
		panic(fmt.Sprintf("inferring schema: %v", err))
	}
	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("marshaling schema: %v", err))
	}
	return b
}
