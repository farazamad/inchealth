// Command phi-scan is a policy-as-code scanner for Terraform plans that flags
// misconfigurations which could expose PHI (protected health information) in
// AWS. It is designed to run as a CI gate:
//
//	terraform plan -out tfplan
//	terraform show -json tfplan > plan.json
//	phi-scan -plan plan.json -fail-on high
//
// It exits non-zero when a finding meets or exceeds the -fail-on threshold.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/farazamad/inchealth/scanner/internal/catalog"
	"github.com/farazamad/inchealth/scanner/internal/plan"
	"github.com/farazamad/inchealth/scanner/internal/report"
	"github.com/farazamad/inchealth/scanner/internal/rules"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("phi-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planPath := fs.String("plan", "-", "path to `terraform show -json` output ('-' for stdin)")
	format := fs.String("format", "table", "output format: table|json|sarif")
	failOn := fs.String("fail-on", "high", "exit non-zero at this severity or above: low|medium|high|critical")
	catalogPath := fs.String("catalog", "", "optional control catalog JSON to annotate findings with framework mappings")
	list := fs.Bool("list-rules", false, "list the rules and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *list {
		for _, r := range rules.All() {
			fmt.Fprintf(stdout, "%-12s %s\n", r.ID, r.Title)
		}
		return 0
	}

	threshold, err := rules.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	idx, err := plan.Load(*planPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	findings := rules.Evaluate(idx)

	if *catalogPath != "" {
		cat, err := catalog.Load(*catalogPath)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		for i := range findings {
			if m := cat.Mappings(findings[i].RuleID); m != nil {
				findings[i].Frameworks = m
			}
		}
	}

	switch report.Normalize(*format) {
	case "json":
		if err := report.JSON(stdout, findings); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	case "sarif":
		if err := report.SARIF(stdout, findings); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	case "table", "":
		report.Table(stdout, findings)
	default:
		fmt.Fprintf(stderr, "error: unknown format %q\n", *format)
		return 2
	}

	if report.MaxSeverity(findings) >= threshold {
		return 1
	}
	return 0
}
