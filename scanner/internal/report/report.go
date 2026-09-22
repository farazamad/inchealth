// Package report renders scanner findings as a human table, JSON, or SARIF
// (for GitHub code scanning).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/farazamad/inchealth/scanner/internal/rules"
)

// Table writes a compact, aligned summary suitable for a terminal or CI log.
func Table(w io.Writer, findings []rules.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ No PHI security findings.")
		return
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity.String()]++
	}
	fmt.Fprintf(w, "Found %d finding(s): %d critical, %d high, %d medium, %d low\n\n",
		len(findings), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
	for _, f := range findings {
		fmt.Fprintf(w, "[%-8s] %s  (%s)\n", f.Severity.String(), f.RuleID, f.Resource)
		fmt.Fprintf(w, "    %s\n", f.Detail)
		fmt.Fprintf(w, "    fix: %s\n\n", f.Remediate)
	}
}

// JSON writes findings as an indented JSON array.
func JSON(w io.Writer, findings []rules.Finding) error {
	if findings == nil {
		findings = []rules.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// SARIF writes a minimal SARIF 2.1.0 document so findings surface in the GitHub
// Security tab via github/codeql-action/upload-sarif.
func SARIF(w io.Writer, findings []rules.Finding) error {
	type rule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []map[string]interface{} `json:"locations"`
	}
	seen := map[string]bool{}
	var ruleDefs []rule
	var results []result
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ruleDefs = append(ruleDefs, rule{ID: f.RuleID, Name: f.Title})
		}
		var r result
		r.RuleID = f.RuleID
		r.Level = sarifLevel(f.Severity)
		r.Message.Text = fmt.Sprintf("%s — %s. Fix: %s", f.Title, f.Detail, f.Remediate)
		r.Locations = []map[string]interface{}{{
			"logicalLocations": []map[string]interface{}{{
				"fullyQualifiedName": f.Resource,
			}},
		}}
		results = append(results, r)
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "phi-scan",
					"informationUri": "https://github.com/farazamad/inchealth",
					"rules":          ruleDefs,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	default:
		return "note"
	}
}

// MaxSeverity returns the highest severity among findings, or -1 if none.
func MaxSeverity(findings []rules.Finding) rules.Severity {
	max := rules.Severity(-1)
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// Normalize trims a format string.
func Normalize(format string) string { return strings.ToLower(strings.TrimSpace(format)) }
