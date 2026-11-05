package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

// The standard decoder matches struct names without regard to case.
// Require the exact spelling of every schema field and reject JSON null.
func validateSchema(data []byte, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("null is outside the schema")
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		if len(fields) != typ.NumField() {
			return errors.New("missing or unknown schema field")
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			raw, ok := fields[field.Tag.Get("json")]
			if !ok {
				return errors.New("schema field spelling does not match")
			}
			if err := validateSchema(raw, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var elements []json.RawMessage
		if err := json.Unmarshal(data, &elements); err != nil {
			return err
		}
		for _, raw := range elements {
			if err := validateSchema(raw, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
