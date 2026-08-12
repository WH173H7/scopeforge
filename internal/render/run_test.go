package render

import (
	"bytes"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

func TestRunTextIsDeterministic(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunPartial,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::1"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.20"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
		},
		Errors: []model.RunError{
			{Code: "timeout", Message: "DNS lookup timed out", Collector: "dns", Target: &target, RecordType: "AAAA", Retryable: true},
		},
	}
	var output bytes.Buffer
	if err := RunText(&output, run); err != nil {
		t.Fatal(err)
	}
	want := "Run partial\n\nTargets\n  DNS  example.com\n\nDNS evidence\n  example.com  A     192.0.2.10\n  example.com  A     192.0.2.20\n  example.com  AAAA  2001:db8::1\n\nCollection failures\n  example.com  AAAA  timeout: DNS lookup timed out\n"
	if output.String() != want {
		t.Fatalf("RunText() = %q, want %q", output.String(), want)
	}
}

func TestRunJSONIsDeterministicAndVersioned(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Status: model.RunCompleted,
		Scope:  model.ScopePolicy{Allowed: []model.Target{target}},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::1"},
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
		},
		Errors: []model.RunError{},
	}
	var output bytes.Buffer
	if err := RunJSON(&output, run); err != nil {
		t.Fatal(err)
	}
	want := "{\"schema_version\":\"1\",\"status\":\"completed\",\"targets\":[{\"kind\":\"dns\",\"value\":\"example.com\"}],\"collectors\":[\"dns\"],\"evidence\":[{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"A\",\"value\":\"192.0.2.10\"},{\"target\":{\"kind\":\"dns\",\"value\":\"example.com\"},\"category\":\"dns_record\",\"record_type\":\"AAAA\",\"value\":\"2001:db8::1\"}],\"errors\":[]}\n"
	if output.String() != want {
		t.Fatalf("RunJSON() = %q, want %q", output.String(), want)
	}
}
