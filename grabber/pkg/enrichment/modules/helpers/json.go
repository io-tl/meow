package helpers

import "fmt"

// JSONGetString safely extracts string from JSON map
func JSONGetString(data interface{}, key string) string {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

// JSONGetInt safely extracts int from JSON map
func JSONGetInt(data interface{}, key string) int {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			switch v := val.(type) {
			case int:
				return v
			case float64:
				return int(v)
			case int64:
				return int(v)
			}
		}
	}
	return 0
}

// JSONGetFloat safely extracts float64 from JSON map
func JSONGetFloat(data interface{}, key string) float64 {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			if f, ok := val.(float64); ok {
				return f
			}
		}
	}
	return 0.0
}

// JSONGetBool safely extracts bool from JSON map
func JSONGetBool(data interface{}, key string) bool {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			if b, ok := val.(bool); ok {
				return b
			}
		}
	}
	return false
}

// JSONGetMap safely extracts map from JSON map
func JSONGetMap(data interface{}, key string) map[string]interface{} {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			if subMap, ok := val.(map[string]interface{}); ok {
				return subMap
			}
		}
	}
	return make(map[string]interface{})
}

// JSONGetArray safely extracts array from JSON map
func JSONGetArray(data interface{}, key string) []interface{} {
	if m, ok := data.(map[string]interface{}); ok {
		if val, exists := m[key]; exists {
			if arr, ok := val.([]interface{}); ok {
				return arr
			}
		}
	}
	return []interface{}{}
}

// JSONGetStringArray safely extracts string array from JSON map
func JSONGetStringArray(data interface{}, key string) []string {
	arr := JSONGetArray(data, key)
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

// JSONGet safely retrieves nested value using dot notation (e.g., "user.name")
func JSONGet(data interface{}, path string) interface{} {
	current := data
	keys := splitPath(path)

	for _, key := range keys {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[key]; exists {
				current = val
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	return current
}

// JSONGetStringNested gets string using dot notation path
func JSONGetStringNested(data interface{}, path string) string {
	val := JSONGet(data, path)
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

// splitPath splits dot-notation path into keys
func splitPath(path string) []string {
	result := []string{}
	current := ""

	for _, ch := range path {
		if ch == '.' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}

// ToJSON converts various types to JSON-safe representations
func ToJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case string, int, int64, float64, bool, nil:
		return val
	case []byte:
		return string(val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
