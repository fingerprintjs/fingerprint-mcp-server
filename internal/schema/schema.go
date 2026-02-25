//go:generate go run -C ../.. ./cmd/generate-schema

package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
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

// FilterProducts nils out fields on the Products struct that are not in the
// requested set. Since all Products fields are pointers tagged with omitempty,
// nilled fields are omitted from the JSON output automatically.
func FilterProducts(p *sdk.Products, fields []string) {
	if p == nil || len(fields) == 0 {
		return
	}

	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}

	v := reflect.ValueOf(p).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		jsonName := strings.SplitN(t.Field(i).Tag.Get("json"), ",", 2)[0]
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

// SearchEventInputToOpts copies matching fields from SearchEventInput to
// sdk.FingerprintApiSearchEventsOpts using reflection. Fields like Limit and
// Products that exist only in SearchEventInput are skipped automatically.
func SearchEventInputToOpts(input *SearchEventInput) *sdk.FingerprintApiSearchEventsOpts {
	opts := &sdk.FingerprintApiSearchEventsOpts{}
	src := reflect.ValueOf(input).Elem()
	dst := reflect.ValueOf(opts).Elem()
	for i := 0; i < dst.NumField(); i++ {
		name := dst.Type().Field(i).Name
		srcField := src.FieldByName(name)
		if srcField.IsValid() && srcField.Type().AssignableTo(dst.Field(i).Type()) {
			dst.Field(i).Set(srcField)
		}
	}
	return opts
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
