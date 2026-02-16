package main

import (
	"reflect"
	"testing"

	"github.com/fingerprintjs/fingerprint-pro-server-api-go-sdk/v7/sdk"
)

// inputOnlyFields lists SearchEventInput fields that intentionally have no
// corresponding field in sdk.FingerprintApiSearchEventsOpts.
var inputOnlyFields = map[string]bool{
	"Limit":    true,
	"Products": true,
}

// Catches SDK adding a new field that our generated SearchEventInput doesn't have yet.
func TestSearchEventInputToOpts_AllOptsFieldsHaveMatchingInputField(t *testing.T) {
	inputType := reflect.TypeOf(SearchEventInput{})
	optsType := reflect.TypeOf(sdk.FingerprintApiSearchEventsOpts{})

	for i := 0; i < optsType.NumField(); i++ {
		optsField := optsType.Field(i)
		inputField, ok := inputType.FieldByName(optsField.Name)
		if !ok {
			t.Errorf("opts field %q has no corresponding field in SearchEventInput", optsField.Name)
			continue
		}
		if !inputField.Type.AssignableTo(optsField.Type) {
			t.Errorf("field %q: SearchEventInput type %s is not assignable to opts type %s",
				optsField.Name, inputField.Type, optsField.Type)
		}
	}
}

// Catches the OpenAPI spec adding a field that the SDK doesn't support, or a typo in the generated name.
func TestSearchEventInputToOpts_AllInputFieldsMapped(t *testing.T) {
	inputType := reflect.TypeOf(SearchEventInput{})
	optsType := reflect.TypeOf(sdk.FingerprintApiSearchEventsOpts{})

	for i := 0; i < inputType.NumField(); i++ {
		name := inputType.Field(i).Name
		if inputOnlyFields[name] {
			continue
		}
		if _, ok := optsType.FieldByName(name); !ok {
			t.Errorf("input field %q has no corresponding field in FingerprintApiSearchEventsOpts and is not in the skip list", name)
		}
	}
}

// Verifies the reflection-based copier actually transfers every value, not just that fields exist.
func TestSearchEventInputToOpts_CopiesAllValues(t *testing.T) {
	// Populate every field of SearchEventInput with a non-zero value via reflection.
	input := SearchEventInput{}
	inputVal := reflect.ValueOf(&input).Elem()
	for i := 0; i < inputVal.NumField(); i++ {
		field := inputVal.Field(i)
		setNonZero(t, inputVal.Type().Field(i).Name, field)
	}

	opts := searchEventInputToOpts(&input)

	// Verify every opts field received a non-zero value.
	optsVal := reflect.ValueOf(opts).Elem()
	optsType := optsVal.Type()
	for i := 0; i < optsType.NumField(); i++ {
		field := optsType.Field(i)
		val := optsVal.Field(i)
		if val.IsZero() {
			t.Errorf("opts field %q is zero after copying from a fully populated input", field.Name)
		}
	}
}

// setNonZero sets a reflect.Value to a non-zero value based on its type.
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
