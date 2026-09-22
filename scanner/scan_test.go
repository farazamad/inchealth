package main

import (
	"io"
	"strings"
	"testing"

	"github.com/farazamad/inchealth/scanner/internal/plan"
	"github.com/farazamad/inchealth/scanner/internal/rules"
)

func evalFixture(t *testing.T, path string) []rules.Finding {
	t.Helper()
	idx, err := plan.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return rules.Evaluate(idx)
}

func findingIDs(fs []rules.Finding) map[string]bool {
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.RuleID] = true
	}
	return ids
}

func TestSecurePlanHasNoBlockingFindings(t *testing.T) {
	findings := evalFixture(t, "testdata/secure.plan.json")
	for _, f := range findings {
		if f.Severity >= rules.High {
			t.Errorf("secure plan produced blocking finding %s on %s: %s", f.RuleID, f.Resource, f.Detail)
		}
	}
}

func TestInsecurePlanFlagsExpectedRules(t *testing.T) {
	findings := evalFixture(t, "testdata/insecure.plan.json")
	ids := findingIDs(findings)
	want := []string{
		"PHI-S3-001",  // no public access block
		"PHI-S3-002",  // no encryption
		"PHI-S3-003",  // no TLS-only policy
		"PHI-S3-004",  // no versioning/logging
		"PHI-IAM-001", // wildcard admin
		"PHI-SG-001",  // postgres open to world
		"PHI-RDS-001", // unencrypted
		"PHI-RDS-002", // publicly accessible
		"PHI-TAG-001", // dynamodb missing classification
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("expected finding %s on insecure plan, but it was not raised", id)
		}
	}
}

func TestInsecurePlanHasCriticalFinding(t *testing.T) {
	findings := evalFixture(t, "testdata/insecure.plan.json")
	max := rules.Severity(-1)
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	if max < rules.Critical {
		t.Errorf("expected at least one CRITICAL finding, got max severity %s", max)
	}
}

func TestRunExitCodes(t *testing.T) {
	// Secure plan should pass the -fail-on high gate.
	if code := run([]string{"-plan", "testdata/secure.plan.json", "-fail-on", "high", "-format", "json"}, io.Discard, io.Discard); code != 0 {
		t.Errorf("secure plan: want exit 0, got %d", code)
	}
	// Insecure plan should fail the gate.
	if code := run([]string{"-plan", "testdata/insecure.plan.json", "-fail-on", "high", "-format", "json"}, io.Discard, io.Discard); code != 1 {
		t.Errorf("insecure plan: want exit 1, got %d", code)
	}
}

func TestSeverityParsing(t *testing.T) {
	if _, err := rules.ParseSeverity("bogus"); err == nil {
		t.Error("expected error for bogus severity")
	}
	for _, s := range []string{"low", "MEDIUM", "High", "critical"} {
		if _, err := rules.ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q) unexpected error: %v", s, err)
		}
	}
}

func TestRulesAreDocumented(t *testing.T) {
	for _, r := range rules.All() {
		if !strings.HasPrefix(r.ID, "PHI-") || r.Title == "" || r.Check == nil {
			t.Errorf("rule %+v is not fully defined", r)
		}
	}
}
