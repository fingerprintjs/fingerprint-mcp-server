package fpmcpserver

import (
	"reflect"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/go-sdk/v8"
)

// Verifies that SearchEventInputToRequest produces a non-zero request when all input fields are set.
func TestSearchEventInputToRequest_AllFieldsPopulated(t *testing.T) {
	// Populate every field of SearchEventInput with a non-zero value via reflection.
	input := schema.SearchEventInput{}
	inputVal := reflect.ValueOf(&input).Elem()
	for i := 0; i < inputVal.NumField(); i++ {
		field := inputVal.Field(i)
		setNonZero(t, inputVal.Type().Field(i).Name, field)
	}

	// Should not panic
	req := schema.SearchEventInputToRequest(&input)

	// Verify req is non-zero (i.e., something was set)
	if reflect.DeepEqual(req, fingerprint.NewSearchEventsRequest()) {
		t.Error("SearchEventInputToRequest returned an empty request from a fully populated input")
	}
}

// setNonZero sets a `reflect.Value` to a non-zero value based on its type.
func setNonZero(t *testing.T, name string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Ptr:
		ptr := reflect.New(v.Type().Elem())
		setNonZero(t, name, ptr.Elem())
		v.Set(ptr)
	case reflect.String:
		v.SetString("test")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(0.5)
	case reflect.Slice:
		slice := reflect.MakeSlice(v.Type(), 1, 1)
		setNonZero(t, name, slice.Index(0))
		v.Set(slice)
	case reflect.Interface:
		v.Set(reflect.ValueOf("test"))
	default:
		t.Fatalf("setNonZero: unsupported kind %s for field %q", v.Kind(), name)
	}
}
