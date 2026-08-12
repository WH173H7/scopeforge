package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

func TestScopeTextIsDeterministic(t *testing.T) {
	policy := model.ScopePolicy{
		Allowed: []model.Target{
			{Kind: model.TargetDNSName, Value: "example.com"},
			{Kind: model.TargetIP, Value: "192.0.2.10"},
		},
	}
	var output bytes.Buffer
	if err := ScopeText(&output, policy, policy.Allowed); err != nil {
		t.Fatal(err)
	}
	want := "Scope valid\n\nTargets\n  DNS  example.com\n  IP   192.0.2.10\n\nExclusions\n  none\n\nEffective targets: 2\n"
	if output.String() != want {
		t.Fatalf("ScopeText() = %q, want %q", output.String(), want)
	}
}

func TestScopeJSONIsDeterministicAndVersioned(t *testing.T) {
	policy := model.ScopePolicy{
		Allowed:  []model.Target{{Kind: model.TargetDNSName, Value: "example.com"}},
		Excluded: []model.Target{},
	}
	var output bytes.Buffer
	if err := ScopeJSON(&output, policy, policy.Allowed); err != nil {
		t.Fatal(err)
	}
	want := "{\"schema_version\":\"1\",\"targets\":[{\"kind\":\"dns\",\"value\":\"example.com\"}],\"exclusions\":[],\"effective_target_count\":1}\n"
	if output.String() != want {
		t.Fatalf("ScopeJSON() = %q, want %q", output.String(), want)
	}

	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("ScopeJSON() produced invalid JSON: %v", err)
	}
	if decoded["schema_version"] != "1" {
		t.Fatalf("schema_version = %#v, want 1", decoded["schema_version"])
	}
}

func TestErrorJSON(t *testing.T) {
	var output bytes.Buffer
	if err := ErrorJSON(&output, "missing_target", "at least one target is required"); err != nil {
		t.Fatal(err)
	}
	want := "{\"error\":{\"code\":\"missing_target\",\"message\":\"at least one target is required\"}}\n"
	if output.String() != want {
		t.Fatalf("ErrorJSON() = %q, want %q", output.String(), want)
	}
}
