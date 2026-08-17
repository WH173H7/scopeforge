package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

func TestRunTextIsDeterministic(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunPartial,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "TXT", Value: "line1\n\r\t\x1b[31mline2"},
			{Target: target, Category: "dns_record", RecordType: "MX", Value: ".", Priority: testPriority(0)},
			{Target: target, Category: "dns_record", RecordType: "NS", Value: "ns2.example.net"},
			{Target: target, Category: "dns_record", RecordType: "MX", Value: "mail2.example.net", Priority: testPriority(20)},
			{Target: target, Category: "dns_record", RecordType: "CNAME", Value: "edge.provider.net"},
			{Target: target, Category: "dns_record", RecordType: "MX", Value: "mail1.example.net", Priority: testPriority(10)},
			{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::1"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.20"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
		},
		Errors: []model.RunError{
			{Code: "evidence_limited", Message: "TXT evidence exceeded retention limits", Collector: "dns", Target: &target, RecordType: "TXT", OmittedRecords: 2, OmittedBytes: 9000},
			{Code: "no_result", Message: "DNS lookup returned no records", Collector: "dns", Target: &target, RecordType: "CNAME"},
			{Code: "timeout", Message: "DNS lookup timed out", Collector: "dns", Target: &target, RecordType: "AAAA", Retryable: true},
		},
	}
	var output bytes.Buffer
	if err := RunText(&output, run); err != nil {
		t.Fatal(err)
	}
	want := "Run partial\n\nTargets\n  DNS  example.com\n\nDNS evidence\n  example.com  A      192.0.2.10\n  example.com  A      192.0.2.20\n  example.com  AAAA   2001:db8::1\n  example.com  CNAME  edge.provider.net\n  example.com  MX     0  .\n  example.com  MX     10  mail1.example.net\n  example.com  MX     20  mail2.example.net\n  example.com  NS     ns2.example.net\n  example.com  TXT    \"line1\\n\\r\\t\\x1b[31mline2\"\n\nDNS absence\n  example.com  CNAME  no records\n\nEvidence limits\n  example.com  TXT    omitted 2 records and 9000 bytes\n\nCollection failures\n  example.com  AAAA  timeout: DNS lookup timed out\n"
	if output.String() != want {
		t.Fatalf("RunText() = %q, want %q", output.String(), want)
	}
}

func TestRunTextQuotesControlCharactersAndPreservesPrintableUnicode(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunCompleted,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "TXT", Value: "café"},
			{Target: target, Category: "dns_record", RecordType: "TXT", Value: "line1\n\r\t\x1b[31mline2"},
		},
	}
	var output bytes.Buffer
	if err := RunText(&output, run); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !bytes.Contains(output.Bytes(), []byte(`  example.com  TXT    "café"`)) {
		t.Fatalf("printable Unicode was escaped or lost: %q", got)
	}
	if !bytes.Contains(output.Bytes(), []byte(`  example.com  TXT    "line1\n\r\t\x1b[31mline2"`)) {
		t.Fatalf("control characters were not escaped: %q", got)
	}
	if bytes.Contains(output.Bytes(), []byte{0x1b}) || bytes.Contains(output.Bytes(), []byte{'\n', 'l'}) {
		t.Fatalf("raw control bytes reached the terminal: %q", got)
	}
}

func TestRunJSONRepresentsEvidenceLimits(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunCompleted, Scope: model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{},
		Errors: []model.RunError{{
			Code: "evidence_limited", Message: "TXT evidence exceeded retention limits",
			Collector: "dns", Target: &target, RecordType: "TXT", OmittedRecords: 3, OmittedBytes: 7000,
		}},
	}
	var output bytes.Buffer
	if err := RunJSON(&output, run); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Errors []struct {
			Code           string `json:"code"`
			OmittedRecords int    `json:"omitted_records"`
			OmittedBytes   int    `json:"omitted_bytes"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != "evidence_limited" || result.Errors[0].OmittedRecords != 3 || result.Errors[0].OmittedBytes != 7000 {
		t.Fatalf("JSON limit outcome = %#v", result.Errors)
	}
}

func testPriority(value uint16) *uint16 {
	return &value
}

func TestRunJSONIsDeterministicAndVersioned(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunCompleted,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "TXT", Value: "YWJj", Encoding: "base64", Truncated: true, OriginalLength: testInt(5000)},
			{Target: target, Category: "dns_record", RecordType: "MX", Value: ".", Priority: testPriority(0)},
			{Target: target, Category: "dns_record", RecordType: "MX", Value: "mail.example.net", Priority: testPriority(10)},
			{Target: target, Category: "dns_record", RecordType: "CNAME", Value: "edge.provider.net"},
			{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::1"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
		},
		Errors: []model.RunError{},
	}
	var output bytes.Buffer
	if err := RunJSON(&output, run); err != nil {
		t.Fatal(err)
	}
	want := "{\"schema_version\":\"1\",\"status\":\"completed\",\"targets\":[{\"kind\":\"dns\",\"value\":\"example.com\"}],\"collectors\":[\"dns\"],\"evidence\":[{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"A\",\"value\":\"192.0.2.10\"},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"AAAA\",\"value\":\"2001:db8::1\"},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"CNAME\",\"value\":\"edge.provider.net\"},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"MX\",\"value\":\".\",\"priority\":0},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"MX\",\"value\":\"mail.example.net\",\"priority\":10},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"TXT\",\"value\":\"YWJj\",\"encoding\":\"base64\",\"truncated\":true,\"original_length\":5000}],\"errors\":[]}\n"
	if output.String() != want {
		t.Fatalf("RunJSON() = %q, want %q", output.String(), want)
	}
}

func TestRunJSONPreservesPrintableTXTUnicode(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunCompleted,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "TXT", Value: "café"},
		},
	}
	var output bytes.Buffer
	if err := RunJSON(&output, run); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"value":"café"`)) {
		t.Fatalf("JSON escaped or altered printable TXT Unicode: %q", output.String())
	}
	if bytes.Contains(output.Bytes(), []byte(`\u00e9`)) {
		t.Fatalf("JSON used ASCII escapes for printable TXT Unicode: %q", output.String())
	}
}

func testInt(value int) *int { return &value }
