package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"unicode/utf8"
)

const MaxInput = 32 * 1024 * 1024

// Decode rejects duplicate fields before decoding the typed schema. Unknown
// fields, trailing documents, invalid UTF-8 and depth over 64 are errors.
func Decode(data []byte, target any) error {
	if len(data) > MaxInput || !utf8.Valid(data) {
		return errors.New("JSON input exceeds limits or is not UTF-8")
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	var visit func(int, string) error
	visit = func(depth int, context string) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds 64")
		}
		token, err := scan.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			keys := map[string]bool{}
			for scan.More() {
				key, err := scan.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] || len(keys) >= 64 {
					return errors.New("duplicate JSON object field or object field budget exceeded")
				}
				keys[name] = true
				if err := visit(depth+1, name); err != nil {
					return err
				}
			}
			_, err = scan.Token()
			return err
		case json.Delim('['):
			limit := 100000
			childContext := ""
			switch context {
			case "checkpoints":
				limit = 256
			case "consistency":
				limit = 255
				childContext = "proof"
			case "inclusions":
				limit = 10000
			case "proof":
				limit = 65
			}
			count := 0
			for scan.More() {
				if count == limit {
					return errors.New("JSON array count exceeds schema budget")
				}
				count++
				if err := visit(depth+1, childContext); err != nil {
					return err
				}
			}
			_, err = scan.Token()
			return err
		}
		return nil
	}
	if err := visit(0, ""); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := scan.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return errors.New("target must be a pointer")
	}
	if err := validateSchema(data, typ.Elem()); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	if err := typed.Decode(target); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return nil
}

func Read(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open JSON input")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxInput+1))
	if err != nil {
		return errors.New("cannot read JSON input")
	}
	return Decode(data, target)
}
