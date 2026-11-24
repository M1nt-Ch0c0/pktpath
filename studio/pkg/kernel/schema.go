// Package kernel implements a DSH/Cordis-inspired microkernel for PktPath Studio
// where every capability (transports, collectors, kernel BTF/qdisc extensions,
// analyzers, exporters, UI slots, and themes) is a hot-reloadable plugin with
// effect-scoped lifecycle management and Schemastery-style visual config forms.
package kernel

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// FieldType defines the UI widget & validation type for a config schema field.
type FieldType string

const (
	FieldString  FieldType = "string"
	FieldNumber  FieldType = "number"
	FieldBoolean FieldType = "boolean"
	FieldSelect  FieldType = "select"
	FieldPath    FieldType = "path"
	FieldFile    FieldType = "file"
	FieldDir     FieldType = "dir"
	FieldList    FieldType = "list" // Repeatable list of structured objects (rendered as visual cards)
)

// FieldOption is one selectable option for FieldSelect.
type FieldOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// FieldSchema describes one configuration field rendered automatically by the
// Studio Schema-Form engine (zero raw JSON editing required for end users).
type FieldSchema struct {
	Key         string        `json:"key"`
	Label       string        `json:"label"`
	Description string        `json:"description,omitempty"`
	Type        FieldType     `json:"type"`
	Default     any           `json:"default,omitempty"`
	Required    bool          `json:"required,omitempty"`
	Placeholder string        `json:"placeholder,omitempty"`
	Min         *float64      `json:"min,omitempty"`
	Max         *float64      `json:"max,omitempty"`
	Step        *float64      `json:"step,omitempty"`
	Unit        string        `json:"unit,omitempty"`
	Group       string        `json:"group,omitempty"`
	Options     []FieldOption `json:"options,omitempty"`
	FileFilter  string        `json:"file_filter,omitempty"`
	ItemLabel   string        `json:"item_label,omitempty"`
	ItemFields  []FieldSchema `json:"item_fields,omitempty"`
}

// ConfigSchema declares the full typed configuration schema of a plugin.
type ConfigSchema struct {
	Title       string        `json:"title,omitempty"`
	Description string        `json:"description,omitempty"`
	Fields      []FieldSchema `json:"fields"`
}

// FloatPtr is a helper for schema Min/Max/Step pointers.
func FloatPtr(v float64) *float64 { return &v }

// DeepCloneValue creates a safe deep copy of JSON-compatible values.
func DeepCloneValue(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

// DefaultConfig produces a fresh default config map from a ConfigSchema.
func DefaultConfig(schema *ConfigSchema) map[string]any {
	out := map[string]any{}
	if schema == nil {
		return out
	}
	for _, f := range schema.Fields {
		if f.Default != nil {
			out[f.Key] = DeepCloneValue(f.Default)
			continue
		}
		switch f.Type {
		case FieldBoolean:
			out[f.Key] = false
		case FieldNumber:
			if f.Min != nil {
				out[f.Key] = *f.Min
			} else {
				out[f.Key] = float64(0)
			}
		case FieldList:
			out[f.Key] = []any{}
		case FieldSelect:
			if len(f.Options) > 0 {
				out[f.Key] = f.Options[0].Value
			} else {
				out[f.Key] = ""
			}
		default:
			out[f.Key] = ""
		}
	}
	return out
}

// NormalizeAndValidate fills missing defaults and validates raw user config against schema.
func NormalizeAndValidate(schema *ConfigSchema, raw map[string]any) (map[string]any, error) {
	if schema == nil || len(schema.Fields) == 0 {
		out := map[string]any{}
		for k, v := range raw {
			out[k] = DeepCloneValue(v)
		}
		return out, nil
	}
	return normalizeObjectFields(schema.Fields, raw, "")
}

func normalizeObjectFields(fields []FieldSchema, raw map[string]any, prefix string) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range fields {
		fullKey := f.Key
		if prefix != "" {
			fullKey = prefix + "." + f.Key
		}
		var val any
		var exists bool
		if raw != nil {
			val, exists = raw[f.Key]
		}
		if !exists || val == nil {
			if f.Default != nil {
				val = DeepCloneValue(f.Default)
			} else {
				switch f.Type {
				case FieldBoolean:
					val = false
				case FieldNumber:
					val = float64(0)
				case FieldList:
					val = []any{}
				case FieldSelect:
					if len(f.Options) > 0 {
						val = f.Options[0].Value
					} else {
						val = ""
					}
				default:
					val = ""
				}
			}
		}

		norm, err := normalizeFieldValue(f, val, fullKey)
		if err != nil {
			return nil, err
		}
		out[f.Key] = norm
	}
	return out, nil
}

func normalizeFieldValue(f FieldSchema, val any, fullKey string) (any, error) {
	switch f.Type {
	case FieldBoolean:
		b, ok := toBool(val)
		if !ok {
			return nil, fmt.Errorf("配置项 %s 需要布尔值", fullKey)
		}
		return b, nil

	case FieldNumber:
		n, ok := toFloat(val)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("配置项 %s 需要有效数字", fullKey)
		}
		if f.Min != nil && n < *f.Min {
			return nil, fmt.Errorf("配置项 %s (%v) 小于最小值 %v", fullKey, n, *f.Min)
		}
		if f.Max != nil && n > *f.Max {
			return nil, fmt.Errorf("配置项 %s (%v) 大于最大值 %v", fullKey, n, *f.Max)
		}
		return n, nil

	case FieldSelect:
		s := strings.TrimSpace(fmt.Sprint(val))
		if len(f.Options) > 0 {
			matched := false
			for _, opt := range f.Options {
				if opt.Value == s {
					matched = true
					break
				}
			}
			if !matched {
				if s == "" && !f.Required {
					return f.Options[0].Value, nil
				}
				return nil, fmt.Errorf("配置项 %s 的值 %q 不在可选项中", fullKey, s)
			}
		}
		return s, nil

	case FieldList:
		items, ok := toSlice(val)
		if !ok {
			return nil, fmt.Errorf("配置项 %s 需要列表", fullKey)
		}
		normList := make([]any, 0, len(items))
		for idx, item := range items {
			if len(f.ItemFields) > 0 {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("配置项 %s[%d] 需要对象结构", fullKey, idx)
				}
				nm, err := normalizeObjectFields(f.ItemFields, m, fmt.Sprintf("%s[%d]", fullKey, idx))
				if err != nil {
					return nil, err
				}
				normList = append(normList, nm)
			} else {
				normList = append(normList, DeepCloneValue(item))
			}
		}
		return normList, nil

	default: // string, path, file, dir
		s := ""
		if val != nil {
			s = strings.TrimSpace(fmt.Sprint(val))
		}
		if f.Required && s == "" {
			return nil, fmt.Errorf("配置项 %s (%s) 不能为空", f.Label, fullKey)
		}
		return s, nil
	}
}

func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		l := strings.ToLower(strings.TrimSpace(x))
		if l == "true" || l == "1" || l == "yes" {
			return true, true
		}
		if l == "false" || l == "0" || l == "no" || l == "" {
			return false, true
		}
	case float64:
		return x != 0, true
	case int:
		return x != 0, true
	}
	return false, false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, true
		}
		var f float64
		if _, err := fmt.Sscanf(s, "%f", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func toSlice(v any) ([]any, bool) {
	if v == nil {
		return []any{}, true
	}
	if s, ok := v.([]any); ok {
		return s, true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var out []any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false
	}
	return out, true
}

// ConfigString extracts a string from a normalized config map.
func ConfigString(cfg map[string]any, key, def string) string {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key]; ok && v != nil {
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" {
			return s
		}
	}
	return def
}

// ConfigBool extracts a bool from a normalized config map.
func ConfigBool(cfg map[string]any, key string, def bool) bool {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key]; ok {
		if b, ok2 := toBool(v); ok2 {
			return b
		}
	}
	return def
}

// ConfigFloat extracts a float64 from a normalized config map.
func ConfigFloat(cfg map[string]any, key string, def float64) float64 {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key]; ok {
		if f, ok2 := toFloat(v); ok2 {
			return f
		}
	}
	return def
}

// ConfigInt extracts an int from a normalized config map.
func ConfigInt(cfg map[string]any, key string, def int) int {
	return int(math.Round(ConfigFloat(cfg, key, float64(def))))
}

// ConfigListMaps extracts a list of maps from a normalized config map.
func ConfigListMaps(cfg map[string]any, key string) []map[string]any {
	if cfg == nil {
		return nil
	}
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return nil
	}
	items, ok := toSlice(raw)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
