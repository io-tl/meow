package helpers

import (
	"testing"
)

// --- JSONGetString ---

func TestJSONGetString_Existing(t *testing.T) {
	data := map[string]interface{}{"name": "test"}
	got := JSONGetString(data, "name")
	if got != "test" {
		t.Errorf("got %q, want %q", got, "test")
	}
}

func TestJSONGetString_Absent(t *testing.T) {
	data := map[string]interface{}{"name": "test"}
	got := JSONGetString(data, "missing")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestJSONGetString_WrongType(t *testing.T) {
	data := map[string]interface{}{"name": 42}
	got := JSONGetString(data, "name")
	if got != "" {
		t.Errorf("got %q, want empty for non-string", got)
	}
}

func TestJSONGetString_NilInput(t *testing.T) {
	got := JSONGetString(nil, "name")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestJSONGetString_NonMap(t *testing.T) {
	got := JSONGetString("not a map", "name")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- JSONGetInt ---

func TestJSONGetInt_Int(t *testing.T) {
	data := map[string]interface{}{"count": 42}
	got := JSONGetInt(data, "count")
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestJSONGetInt_Float64(t *testing.T) {
	data := map[string]interface{}{"count": float64(42.0)}
	got := JSONGetInt(data, "count")
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestJSONGetInt_Int64(t *testing.T) {
	data := map[string]interface{}{"count": int64(42)}
	got := JSONGetInt(data, "count")
	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestJSONGetInt_Absent(t *testing.T) {
	data := map[string]interface{}{"count": 42}
	got := JSONGetInt(data, "missing")
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestJSONGetInt_NilInput(t *testing.T) {
	got := JSONGetInt(nil, "count")
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestJSONGetInt_WrongType(t *testing.T) {
	data := map[string]interface{}{"count": "not a number"}
	got := JSONGetInt(data, "count")
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- JSONGetFloat ---

func TestJSONGetFloat_Float(t *testing.T) {
	data := map[string]interface{}{"val": 3.14}
	got := JSONGetFloat(data, "val")
	if got != 3.14 {
		t.Errorf("got %f, want 3.14", got)
	}
}

func TestJSONGetFloat_NonFloat(t *testing.T) {
	data := map[string]interface{}{"val": "string"}
	got := JSONGetFloat(data, "val")
	if got != 0.0 {
		t.Errorf("got %f, want 0.0", got)
	}
}

func TestJSONGetFloat_Absent(t *testing.T) {
	got := JSONGetFloat(map[string]interface{}{}, "missing")
	if got != 0.0 {
		t.Errorf("got %f, want 0.0", got)
	}
}

// --- JSONGetBool ---

func TestJSONGetBool_True(t *testing.T) {
	data := map[string]interface{}{"flag": true}
	got := JSONGetBool(data, "flag")
	if !got {
		t.Error("expected true")
	}
}

func TestJSONGetBool_False(t *testing.T) {
	data := map[string]interface{}{"flag": false}
	got := JSONGetBool(data, "flag")
	if got {
		t.Error("expected false")
	}
}

func TestJSONGetBool_NonBool(t *testing.T) {
	data := map[string]interface{}{"flag": "yes"}
	got := JSONGetBool(data, "flag")
	if got {
		t.Error("expected false for non-bool")
	}
}

func TestJSONGetBool_Absent(t *testing.T) {
	got := JSONGetBool(map[string]interface{}{}, "missing")
	if got {
		t.Error("expected false for missing key")
	}
}

// --- JSONGetMap ---

func TestJSONGetMap_Existing(t *testing.T) {
	inner := map[string]interface{}{"a": "b"}
	data := map[string]interface{}{"sub": inner}
	got := JSONGetMap(data, "sub")
	if got["a"] != "b" {
		t.Errorf("got %v", got)
	}
}

func TestJSONGetMap_NonMap(t *testing.T) {
	data := map[string]interface{}{"sub": "string"}
	got := JSONGetMap(data, "sub")
	if len(got) != 0 {
		t.Errorf("got %v, want empty map", got)
	}
}

func TestJSONGetMap_Absent(t *testing.T) {
	got := JSONGetMap(map[string]interface{}{}, "missing")
	if len(got) != 0 {
		t.Errorf("got %v, want empty map", got)
	}
}

// --- JSONGetArray ---

func TestJSONGetArray_Existing(t *testing.T) {
	data := map[string]interface{}{"items": []interface{}{"a", "b"}}
	got := JSONGetArray(data, "items")
	if len(got) != 2 {
		t.Errorf("got len %d, want 2", len(got))
	}
}

func TestJSONGetArray_NonArray(t *testing.T) {
	data := map[string]interface{}{"items": "string"}
	got := JSONGetArray(data, "items")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestJSONGetArray_Absent(t *testing.T) {
	got := JSONGetArray(map[string]interface{}{}, "missing")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// --- JSONGetStringArray ---

func TestJSONGetStringArray_Strings(t *testing.T) {
	data := map[string]interface{}{"items": []interface{}{"a", "b", "c"}}
	got := JSONGetStringArray(data, "items")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v", got)
	}
}

func TestJSONGetStringArray_Mixed(t *testing.T) {
	data := map[string]interface{}{"items": []interface{}{"a", 42, "b"}}
	got := JSONGetStringArray(data, "items")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("got %v, want [a b]", got)
	}
}

func TestJSONGetStringArray_Empty(t *testing.T) {
	data := map[string]interface{}{"items": []interface{}{}}
	got := JSONGetStringArray(data, "items")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// --- JSONGet (dot path) ---

func TestJSONGet_DeepPath(t *testing.T) {
	data := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": "deep_value",
			},
		},
	}
	got := JSONGet(data, "a.b.c")
	if got != "deep_value" {
		t.Errorf("got %v, want %q", got, "deep_value")
	}
}

func TestJSONGet_AbsentKey(t *testing.T) {
	data := map[string]interface{}{"a": "b"}
	got := JSONGet(data, "x.y.z")
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestJSONGet_PartialPath(t *testing.T) {
	data := map[string]interface{}{
		"a": map[string]interface{}{
			"b": "value",
		},
	}
	got := JSONGet(data, "a.b.c")
	if got != nil {
		t.Errorf("got %v, want nil for path through non-map", got)
	}
}

func TestJSONGet_SingleKey(t *testing.T) {
	data := map[string]interface{}{"key": "val"}
	got := JSONGet(data, "key")
	if got != "val" {
		t.Errorf("got %v, want %q", got, "val")
	}
}

// --- JSONGetStringNested ---

func TestJSONGetStringNested_Valid(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"name": "Alice",
		},
	}
	got := JSONGetStringNested(data, "user.name")
	if got != "Alice" {
		t.Errorf("got %q, want %q", got, "Alice")
	}
}

func TestJSONGetStringNested_Invalid(t *testing.T) {
	data := map[string]interface{}{"a": "b"}
	got := JSONGetStringNested(data, "x.y")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestJSONGetStringNested_NonString(t *testing.T) {
	data := map[string]interface{}{"a": map[string]interface{}{"b": 42}}
	got := JSONGetStringNested(data, "a.b")
	if got != "" {
		t.Errorf("got %q, want empty for non-string value", got)
	}
}

// --- ToJSON ---

func TestToJSON_String(t *testing.T) {
	got := ToJSON("hello")
	if got != "hello" {
		t.Errorf("got %v", got)
	}
}

func TestToJSON_Int(t *testing.T) {
	got := ToJSON(42)
	if got != 42 {
		t.Errorf("got %v", got)
	}
}

func TestToJSON_Bytes(t *testing.T) {
	got := ToJSON([]byte("data"))
	if got != "data" {
		t.Errorf("got %v, want %q", got, "data")
	}
}

func TestToJSON_Nil(t *testing.T) {
	got := ToJSON(nil)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestToJSON_Struct(t *testing.T) {
	type S struct{ Name string }
	got := ToJSON(S{Name: "test"})
	str, ok := got.(string)
	if !ok {
		t.Fatalf("expected string, got %T", got)
	}
	if str == "" {
		t.Error("expected non-empty string")
	}
}

func TestToJSON_Bool(t *testing.T) {
	got := ToJSON(true)
	if got != true {
		t.Errorf("got %v, want true", got)
	}
}

func TestToJSON_Float64(t *testing.T) {
	got := ToJSON(3.14)
	if got != 3.14 {
		t.Errorf("got %v, want 3.14", got)
	}
}
