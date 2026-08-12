package scope

import (
	"strings"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  model.Target
	}{
		{name: "DNS normalization", input: "API.Example.COM.", want: model.Target{Kind: model.TargetDNSName, Value: "api.example.com"}},
		{name: "IPv4", input: "192.0.2.8", want: model.Target{Kind: model.TargetIP, Value: "192.0.2.8"}},
		{name: "IPv6 normalization", input: "2001:0db8::1", want: model.Target{Kind: model.TargetIP, Value: "2001:db8::1"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseTarget(test.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) returned error: %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("ParseTarget(%q) = %#v, want %#v", test.input, got, test.want)
			}
		})
	}
}

func TestParseTargetRejectsInvalidValues(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	tests := []string{
		"",
		" example.com",
		"https://example.com",
		"*.example.com",
		"-edge.example.com",
		"edge-.example.com",
		"edge..example.com",
		"999.999.999.999",
		"192.168.001.001",
		longLabel,
		"café.example",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseTarget(input); err == nil {
				t.Fatalf("ParseTarget(%q) succeeded, want error", input)
			}
		})
	}
}

func TestPolicyIsDenyByDefault(t *testing.T) {
	policy, err := NewPolicy([]string{"example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	allowed, _ := ParseTarget("example.com")
	subdomain, _ := ParseTarget("www.example.com")
	if !Allows(policy, allowed) {
		t.Fatal("explicit target was denied")
	}
	if Allows(policy, subdomain) {
		t.Fatal("subdomain was implicitly allowed")
	}
}

func TestPolicyExclusionWins(t *testing.T) {
	policy, err := NewPolicy([]string{"example.com"}, []string{"EXAMPLE.COM."})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := ParseTarget("example.com")
	if Allows(policy, target) {
		t.Fatal("excluded target was allowed")
	}
}

func TestNewPolicyRemovesNormalizedDuplicates(t *testing.T) {
	policy, err := NewPolicy(
		[]string{"example.com", "EXAMPLE.COM."},
		[]string{"192.0.2.1", "192.0.2.1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Allowed) != 1 {
		t.Fatalf("len(policy.Allowed) = %d, want 1", len(policy.Allowed))
	}
	if len(policy.Excluded) != 1 {
		t.Fatalf("len(policy.Excluded) = %d, want 1", len(policy.Excluded))
	}
}

func TestEffectiveTargetsAppliesExclusions(t *testing.T) {
	policy, err := NewPolicy(
		[]string{"example.com", "192.0.2.1"},
		[]string{"EXAMPLE.COM."},
	)
	if err != nil {
		t.Fatal(err)
	}

	effective := EffectiveTargets(policy)
	want := []model.Target{{Kind: model.TargetIP, Value: "192.0.2.1"}}
	if len(effective) != len(want) || effective[0] != want[0] {
		t.Fatalf("EffectiveTargets() = %#v, want %#v", effective, want)
	}
}
