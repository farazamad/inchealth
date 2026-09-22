// Package plan loads and normalizes a Terraform plan produced with
//
//	terraform plan -out tfplan && terraform show -json tfplan > plan.json
//
// It intentionally depends only on the Go standard library so the scanner can
// be built and run in air-gapped CI runners without fetching modules.
package plan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Plan is the subset of the Terraform JSON plan format the scanner reads.
type Plan struct {
	FormatVersion string `json:"format_version"`
	PlannedValues struct {
		RootModule Module `json:"root_module"`
	} `json:"planned_values"`
}

// Module mirrors a Terraform module in the planned values tree.
type Module struct {
	Resources    []Resource `json:"resources"`
	ChildModules []Module   `json:"child_modules"`
	Address      string     `json:"address"`
}

// Resource is a single planned resource plus its attribute values.
type Resource struct {
	Address string                 `json:"address"`
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Values  map[string]interface{} `json:"values"`
}

// Index is a flattened, query-friendly view of every resource in the plan.
type Index struct {
	Resources []Resource
	byType    map[string][]Resource
}

// Load reads a plan from a file path, or from stdin when path is "-".
func Load(path string) (*Index, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open plan: %w", err)
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}

	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse plan JSON (is this `terraform show -json`?): %w", err)
	}

	idx := &Index{byType: map[string][]Resource{}}
	idx.walk(p.PlannedValues.RootModule)
	return idx, nil
}

func (idx *Index) walk(m Module) {
	for _, res := range m.Resources {
		idx.Resources = append(idx.Resources, res)
		idx.byType[res.Type] = append(idx.byType[res.Type], res)
	}
	for _, child := range m.ChildModules {
		idx.walk(child)
	}
}

// OfType returns every resource of the given Terraform type.
func (idx *Index) OfType(t string) []Resource {
	return idx.byType[t]
}

// String returns a string attribute, following simple dotted paths like
// "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm"
// across nested maps and single-element lists (how Terraform renders blocks).
func (r Resource) String(path string) (string, bool) {
	v, ok := r.lookup(path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Bool returns a boolean attribute at the given path.
func (r Resource) Bool(path string) (bool, bool) {
	v, ok := r.lookup(path)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// Tag returns the value of a tag (checked under both "tags" and "tags_all").
func (r Resource) Tag(key string) (string, bool) {
	for _, bag := range []string{"tags", "tags_all"} {
		if raw, ok := r.Values[bag]; ok {
			if m, ok := raw.(map[string]interface{}); ok {
				if v, ok := m[key]; ok {
					if s, ok := v.(string); ok {
						return s, true
					}
				}
			}
		}
	}
	return "", false
}

func (r Resource) lookup(path string) (interface{}, bool) {
	var cur interface{} = r.Values
	for _, part := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]interface{}:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []interface{}:
			// Terraform renders single blocks as one-element lists; descend.
			if len(node) == 0 {
				return nil, false
			}
			m, ok := node[0].(map[string]interface{})
			if !ok {
				return nil, false
			}
			next, ok := m[part]
			if !ok {
				return nil, false
			}
			cur = next
		default:
			return nil, false
		}
	}
	return cur, true
}
