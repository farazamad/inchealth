// Package catalog loads the shared control catalog (compliance/controls.json)
// so the scanner can annotate each finding with the compliance-framework
// requirements it maps to. The same file is the single source of truth for the
// Python compliance report generator.
package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// Framework describes a compliance framework referenced by the catalog.
type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Control is one catalog entry mapping an internal check to framework IDs.
type Control struct {
	ID        string              `json:"id"`
	Title     string              `json:"title"`
	Type      string              `json:"type"`      // automated | runtime | manual
	Component string              `json:"component"` // phi-scan | jit_access | ...
	Mappings  map[string][]string `json:"mappings"`  // framework key -> control IDs
}

// Catalog is the whole crosswalk document.
type Catalog struct {
	Frameworks map[string]Framework `json:"frameworks"`
	Controls   []Control            `json:"controls"`

	byID map[string]Control
}

// Load reads and indexes the catalog from a JSON file.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog JSON: %w", err)
	}
	c.byID = make(map[string]Control, len(c.Controls))
	for _, ctrl := range c.Controls {
		c.byID[ctrl.ID] = ctrl
	}
	return &c, nil
}

// Mappings returns the framework crosswalk for a control/rule ID, or nil.
func (c *Catalog) Mappings(id string) map[string][]string {
	if c == nil {
		return nil
	}
	if ctrl, ok := c.byID[id]; ok {
		return ctrl.Mappings
	}
	return nil
}
