// Package rules holds the policy-as-code checks the scanner evaluates against a
// Terraform plan. Each rule targets a concrete way PHI (protected health
// information) can leak or a HIPAA safeguard can be missed in AWS.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/farazamad/inchealth/scanner/internal/plan"
)

// Severity ranks findings so CI can gate on a threshold.
type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ParseSeverity converts a threshold flag value into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(s) {
	case "LOW":
		return Low, nil
	case "MEDIUM":
		return Medium, nil
	case "HIGH":
		return High, nil
	case "CRITICAL":
		return Critical, nil
	}
	return Low, fmt.Errorf("unknown severity %q (want low|medium|high|critical)", s)
}

// Finding is a single rule violation on a specific resource.
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Title     string   `json:"title"`
	Severity  Severity `json:"-"`
	SeverityS string   `json:"severity"`
	Resource  string   `json:"resource"`
	Detail    string   `json:"detail"`
	Remediate string   `json:"remediation"`
}

// Rule evaluates the whole plan and returns any violations it finds.
type Rule struct {
	ID    string
	Title string
	Check func(idx *plan.Index) []Finding
}

// phiSensitivities are the data-classification tag values that mark a resource
// as in-scope for the strictest PHI controls.
var phiSensitivities = map[string]bool{
	"phi": true, "restricted": true, "pii": true, "confidential": true,
}

// isPHI reports whether a resource is classified as handling sensitive data,
// via an explicit data_classification tag or a naming hint. This is how data
// classification is wired directly into the security controls.
func isPHI(r plan.Resource) bool {
	if v, ok := r.Tag("data_classification"); ok && phiSensitivities[strings.ToLower(v)] {
		return true
	}
	name := strings.ToLower(r.Address)
	for _, hint := range []string{"phi", "pii", "patient", "clinical", "health", "member"} {
		if strings.Contains(name, hint) {
			return true
		}
	}
	return false
}

// All returns the full ruleset in a stable order.
func All() []Rule {
	return []Rule{
		s3PublicAccessBlock(),
		s3Encryption(),
		s3TLSOnly(),
		s3VersioningLogging(),
		iamWildcard(),
		sgOpenIngress(),
		rdsHardening(),
		classificationTag(),
	}
}

// Evaluate runs every rule and returns findings sorted by severity desc.
func Evaluate(idx *plan.Index) []Finding {
	var out []Finding
	for _, rule := range All() {
		out = append(out, rule.Check(idx)...)
	}
	for i := range out {
		out[i].SeverityS = out[i].Severity.String()
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// --- individual rules -------------------------------------------------------

// bucketNames maps a bucket's literal name to its resource address so companion
// resources (encryption, public-access-block) can be matched to their bucket.
func bucketNames(idx *plan.Index) map[string]string {
	m := map[string]string{}
	for _, b := range idx.OfType("aws_s3_bucket") {
		if name, ok := b.String("bucket"); ok {
			m[name] = b.Address
		}
	}
	return m
}

// companionBuckets returns the set of bucket names referenced by a companion
// resource type (matched on the literal `bucket` attribute).
func companionBuckets(idx *plan.Index, resType string) map[string]plan.Resource {
	m := map[string]plan.Resource{}
	for _, r := range idx.OfType(resType) {
		if b, ok := r.String("bucket"); ok {
			m[b] = r
		}
	}
	return m
}

func s3PublicAccessBlock() Rule {
	return Rule{
		ID:    "PHI-S3-001",
		Title: "S3 bucket must block all public access",
		Check: func(idx *plan.Index) []Finding {
			pab := companionBuckets(idx, "aws_s3_bucket_public_access_block")
			var out []Finding
			for name, addr := range bucketNames(idx) {
				block, ok := pab[name]
				flags := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
				missing := []string{}
				if !ok {
					missing = flags
				} else {
					for _, f := range flags {
						if v, ok := block.Bool(f); !ok || !v {
							missing = append(missing, f)
						}
					}
				}
				if len(missing) > 0 {
					out = append(out, Finding{
						RuleID: "PHI-S3-001", Title: "S3 bucket must block all public access",
						Severity: Critical, Resource: addr,
						Detail:    fmt.Sprintf("bucket %q is missing public-access-block flags: %s", name, strings.Join(missing, ", ")),
						Remediate: "Attach an aws_s3_bucket_public_access_block with all four flags set to true.",
					})
				}
			}
			return out
		},
	}
}

func s3Encryption() Rule {
	return Rule{
		ID:    "PHI-S3-002",
		Title: "S3 bucket holding PHI must be encrypted with KMS",
		Check: func(idx *plan.Index) []Finding {
			enc := companionBuckets(idx, "aws_s3_bucket_server_side_encryption_configuration")
			var out []Finding
			for name, addr := range bucketNames(idx) {
				cfg, ok := enc[name]
				sev := High
				var detail string
				switch {
				case !ok:
					detail = fmt.Sprintf("bucket %q has no server-side encryption configuration", name)
				default:
					alg, _ := cfg.String("rule.apply_server_side_encryption_by_default.sse_algorithm")
					if alg == "aws:kms" {
						continue
					}
					if alg == "" {
						detail = fmt.Sprintf("bucket %q encryption configuration does not set an algorithm", name)
					} else {
						sev = Medium
						detail = fmt.Sprintf("bucket %q uses %q; PHI requires customer-managed KMS (aws:kms)", name, alg)
					}
				}
				out = append(out, Finding{
					RuleID: "PHI-S3-002", Title: "S3 bucket holding PHI must be encrypted with KMS",
					Severity: sev, Resource: addr, Detail: detail,
					Remediate: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\" and a customer-managed key.",
				})
			}
			return out
		},
	}
}

func s3TLSOnly() Rule {
	return Rule{
		ID:    "PHI-S3-003",
		Title: "S3 bucket policy must deny non-TLS (aws:SecureTransport) access",
		Check: func(idx *plan.Index) []Finding {
			// Look for a bucket policy that denies insecure transport.
			secured := map[string]bool{}
			for _, p := range idx.OfType("aws_s3_bucket_policy") {
				policy, _ := p.String("policy")
				if strings.Contains(policy, "aws:SecureTransport") {
					if b, ok := p.String("bucket"); ok {
						secured[b] = true
					}
				}
			}
			var out []Finding
			for name, addr := range bucketNames(idx) {
				if !secured[name] {
					out = append(out, Finding{
						RuleID: "PHI-S3-003", Title: "S3 bucket policy must deny non-TLS access",
						Severity: Medium, Resource: addr,
						Detail:    fmt.Sprintf("bucket %q has no policy denying aws:SecureTransport=false", name),
						Remediate: "Attach a bucket policy with a Deny on aws:SecureTransport false to enforce encryption in transit.",
					})
				}
			}
			return out
		},
	}
}

func s3VersioningLogging() Rule {
	return Rule{
		ID:    "PHI-S3-004",
		Title: "S3 bucket should enable versioning and access logging",
		Check: func(idx *plan.Index) []Finding {
			versioned := companionBuckets(idx, "aws_s3_bucket_versioning")
			logged := companionBuckets(idx, "aws_s3_bucket_logging")
			var out []Finding
			for name, addr := range bucketNames(idx) {
				var problems []string
				if v, ok := versioned[name]; !ok {
					problems = append(problems, "versioning not configured")
				} else if status, _ := v.String("versioning_configuration.status"); status != "Enabled" {
					problems = append(problems, "versioning not Enabled")
				}
				if _, ok := logged[name]; !ok {
					problems = append(problems, "access logging not configured")
				}
				if len(problems) > 0 {
					out = append(out, Finding{
						RuleID: "PHI-S3-004", Title: "S3 bucket should enable versioning and access logging",
						Severity: Medium, Resource: addr,
						Detail:    fmt.Sprintf("bucket %q: %s", name, strings.Join(problems, "; ")),
						Remediate: "Add aws_s3_bucket_versioning (Enabled) and aws_s3_bucket_logging for audit and recovery.",
					})
				}
			}
			return out
		},
	}
}

func iamWildcard() Rule {
	return Rule{
		ID:    "PHI-IAM-001",
		Title: "IAM policy must not grant Action:* on Resource:*",
		Check: func(idx *plan.Index) []Finding {
			var out []Finding
			for _, res := range append(idx.OfType("aws_iam_policy"), idx.OfType("aws_iam_role_policy")...) {
				policy, ok := res.String("policy")
				if !ok {
					continue
				}
				flat := strings.Join(strings.Fields(policy), "")
				if strings.Contains(flat, `"Action":"*"`) && strings.Contains(flat, `"Resource":"*"`) {
					out = append(out, Finding{
						RuleID: "PHI-IAM-001", Title: "IAM policy must not grant Action:* on Resource:*",
						Severity: High, Resource: res.Address,
						Detail:    "policy grants full administrative access (Action \"*\" on Resource \"*\")",
						Remediate: "Scope actions and resources to the least privilege the workload actually needs.",
					})
				}
			}
			return out
		},
	}
}

// sensitivePorts are commonly attacked management/database ports.
var sensitivePorts = map[int]string{22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}

func sgOpenIngress() Rule {
	return Rule{
		ID:    "PHI-SG-001",
		Title: "Security group must not expose sensitive ports to 0.0.0.0/0",
		Check: func(idx *plan.Index) []Finding {
			var out []Finding
			check := func(addr string, from, to float64, cidrs []interface{}) *Finding {
				open := false
				for _, c := range cidrs {
					if s, ok := c.(string); ok && (s == "0.0.0.0/0" || s == "::/0") {
						open = true
					}
				}
				if !open {
					return nil
				}
				for port, svc := range sensitivePorts {
					if float64(port) >= from && float64(port) <= to {
						return &Finding{
							RuleID: "PHI-SG-001", Title: "Security group must not expose sensitive ports to 0.0.0.0/0",
							Severity: Critical, Resource: addr,
							Detail:    fmt.Sprintf("ingress %d-%d open to the internet exposes %s", int(from), int(to), svc),
							Remediate: "Restrict ingress to known CIDRs / security groups; reach production over SSM or a bastion, never 0.0.0.0/0.",
						}
					}
				}
				return nil
			}
			// Standalone rule resources.
			for _, r := range idx.OfType("aws_security_group_rule") {
				if t, _ := r.String("type"); t != "ingress" {
					continue
				}
				from, _ := numeric(r.Values["from_port"])
				to, _ := numeric(r.Values["to_port"])
				cidrs, _ := r.Values["cidr_blocks"].([]interface{})
				if f := check(r.Address, from, to, cidrs); f != nil {
					out = append(out, *f)
				}
			}
			// Inline ingress blocks on the security group.
			for _, sg := range idx.OfType("aws_security_group") {
				ingress, _ := sg.Values["ingress"].([]interface{})
				for _, raw := range ingress {
					m, ok := raw.(map[string]interface{})
					if !ok {
						continue
					}
					from, _ := numeric(m["from_port"])
					to, _ := numeric(m["to_port"])
					cidrs, _ := m["cidr_blocks"].([]interface{})
					if f := check(sg.Address, from, to, cidrs); f != nil {
						out = append(out, *f)
					}
				}
			}
			return out
		},
	}
}

func rdsHardening() Rule {
	return Rule{
		ID:    "PHI-RDS-001",
		Title: "RDS instances must be encrypted and not publicly accessible",
		Check: func(idx *plan.Index) []Finding {
			var out []Finding
			for _, db := range idx.OfType("aws_db_instance") {
				if enc, ok := db.Bool("storage_encrypted"); !ok || !enc {
					out = append(out, Finding{
						RuleID: "PHI-RDS-001", Title: "RDS instances must be encrypted at rest",
						Severity: High, Resource: db.Address,
						Detail:    "storage_encrypted is not true",
						Remediate: "Set storage_encrypted = true with a KMS key for PHI databases.",
					})
				}
				if pub, ok := db.Bool("publicly_accessible"); ok && pub {
					out = append(out, Finding{
						RuleID: "PHI-RDS-002", Title: "RDS instances must not be publicly accessible",
						Severity: Critical, Resource: db.Address,
						Detail:    "publicly_accessible is true",
						Remediate: "Set publicly_accessible = false and place the instance in private subnets.",
					})
				}
			}
			return out
		},
	}
}

func classificationTag() Rule {
	// Data-store resource types that must carry a data_classification tag so
	// downstream access control and monitoring can reason about sensitivity.
	dataStores := []string{"aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table", "aws_rds_cluster", "aws_efs_file_system"}
	return Rule{
		ID:    "PHI-TAG-001",
		Title: "Data stores must carry a data_classification tag",
		Check: func(idx *plan.Index) []Finding {
			var out []Finding
			for _, t := range dataStores {
				for _, r := range idx.OfType(t) {
					if _, ok := r.Tag("data_classification"); !ok {
						out = append(out, Finding{
							RuleID: "PHI-TAG-001", Title: "Data stores must carry a data_classification tag",
							Severity: Medium, Resource: r.Address,
							Detail:    "no data_classification tag; access control and DLP cannot reason about this resource",
							Remediate: "Tag the resource with data_classification = public|internal|confidential|phi.",
						})
					}
				}
			}
			return out
		},
	}
}

func numeric(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}
