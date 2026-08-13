package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

type commandResolver struct {
	responses map[string][]net.IP
	errors    map[string]error
	mx        map[string][]*net.MX
	ns        map[string][]*net.NS
	cname     map[string]string
	txt       map[string][]string
	calls     []string
}

func (resolver *commandResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	resolver.calls = append(resolver.calls, "txt:"+host)
	return resolver.txt[host], resolver.errors["txt:"+host]
}

func (resolver *commandResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	resolver.calls = append(resolver.calls, network+":"+host)
	return resolver.responses[network+":"+host], resolver.errors[network+":"+host]
}

func (resolver *commandResolver) LookupMX(_ context.Context, host string) ([]*net.MX, error) {
	resolver.calls = append(resolver.calls, "mx:"+host)
	return resolver.mx[host], resolver.errors["mx:"+host]
}

func (resolver *commandResolver) LookupNS(_ context.Context, host string) ([]*net.NS, error) {
	resolver.calls = append(resolver.calls, "ns:"+host)
	return resolver.ns[host], resolver.errors["ns:"+host]
}

func (resolver *commandResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	resolver.calls = append(resolver.calls, "cname:"+host)
	return resolver.cname[host], resolver.errors["cname:"+host]
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(stdout.String(), "Usage: scopeforge") {
		t.Fatalf("run() stdout = %q, want usage", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestValidateScopeText(t *testing.T) {
	exitCode, stdout, stderr := runCommand(
		"validate-scope",
		"--target", "192.0.2.10",
		"--target", "Example.COM.",
		"--exclude", "198.51.100.2",
		"--exclude", "203.0.113.3",
	)
	if exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, exitSuccess, stderr)
	}
	want := "Scope valid\n\nTargets\n  DNS  example.com\n  IP   192.0.2.10\n\nExclusions\n  IP   198.51.100.2\n  IP   203.0.113.3\n\nEffective targets: 2\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestValidateScopeJSONDeduplicatesNormalizedTargets(t *testing.T) {
	exitCode, stdout, stderr := runCommand(
		"validate-scope",
		"--target", "Example.COM.",
		"--target", "example.com",
		"--target", "192.0.2.10",
		"--format", "json",
	)
	if exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, exitSuccess, stderr)
	}
	want := "{\"schema_version\":\"1\",\"targets\":[{\"kind\":\"dns\",\"value\":\"example.com\"},{\"kind\":\"ip\",\"value\":\"192.0.2.10\"}],\"exclusions\":[],\"effective_target_count\":2}\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var result struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if result.SchemaVersion != "1" {
		t.Fatalf("schema_version = %q, want 1", result.SchemaVersion)
	}
}

func TestValidateScopeExpectedErrors(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode string
		wantExit int
	}{
		{name: "missing target", args: []string{"validate-scope"}, wantCode: "missing_target", wantExit: exitValidation},
		{name: "malformed DNS", args: []string{"validate-scope", "--target", "edge..example.com"}, wantCode: "invalid_target", wantExit: exitValidation},
		{name: "malformed IPv4-like", args: []string{"validate-scope", "--target", "999.999.999.999"}, wantCode: "invalid_target", wantExit: exitValidation},
		{name: "malformed exclusion", args: []string{"validate-scope", "--target", "example.com", "--exclude", "*.example.com"}, wantCode: "invalid_exclusion", wantExit: exitValidation},
		{name: "empty effective scope", args: []string{"validate-scope", "--target", "example.com", "--exclude", "EXAMPLE.COM."}, wantCode: "empty_effective_scope", wantExit: exitValidation},
		{name: "invalid format", args: []string{"validate-scope", "--target", "example.com", "--format", "yaml"}, wantCode: "invalid_format", wantExit: exitUsage},
		{name: "unknown flag", args: []string{"validate-scope", "--unknown"}, wantCode: "invalid_usage", wantExit: exitUsage},
		{name: "positional argument", args: []string{"validate-scope", "example.com"}, wantCode: "invalid_usage", wantExit: exitUsage},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exitCode, stdout, stderr := runCommand(test.args...)
			if exitCode != test.wantExit {
				t.Fatalf("exit code = %d, want %d", exitCode, test.wantExit)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, test.wantCode) {
				t.Fatalf("stderr = %q, want code %q", stderr, test.wantCode)
			}
		})
	}
}

func TestValidateScopeJSONErrorUsesStdoutOnly(t *testing.T) {
	exitCode, stdout, stderr := runCommand(
		"validate-scope", "--target", "edge..example.com", "--format", "json",
	)
	if exitCode != exitValidation {
		t.Fatalf("exit code = %d, want %d", exitCode, exitValidation)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	want := "{\"error\":{\"code\":\"invalid_target\",\"message\":\"target is invalid\"}}\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

func TestValidateScopeDoesNotAuthorizeSubdomains(t *testing.T) {
	exitCode, stdout, stderr := runCommand(
		"validate-scope",
		"--target", "example.com",
		"--exclude", "api.example.com",
	)
	if exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, exitSuccess, stderr)
	}
	if !strings.Contains(stdout, "Effective targets: 1") {
		t.Fatalf("stdout = %q, want one effective target", stdout)
	}
}

func TestRunDNSCollectsAuthorizedTargets(t *testing.T) {
	resolver := &commandResolver{responses: map[string][]net.IP{
		"ip4:example.com": {net.ParseIP("192.0.2.20"), net.ParseIP("192.0.2.10")},
		"ip6:example.com": {net.ParseIP("2001:db8::1")},
		"ip4:example.org": {net.ParseIP("198.51.100.10")},
		"ip6:example.org": {net.ParseIP("2001:db8::2")},
	}, mx: map[string][]*net.MX{
		"example.com": {{Host: "mail.example.net.", Pref: 10}},
		"example.org": {{Host: "mail.example.org.", Pref: 20}},
	}, ns: map[string][]*net.NS{
		"example.com": {{Host: "ns.example.net."}},
		"example.org": {{Host: "ns.example.org."}},
	}, cname: map[string]string{
		"example.com": "edge.example.net.", "example.org": "example.org.",
	}, txt: map[string][]string{
		"example.com": {"Verification=Ab C"}, "example.org": {},
	}}
	exitCode, stdout, stderr := runReconCommand(
		context.Background(), resolver,
		"run", "--target", "example.org", "--target", "example.com", "--collect", "dns",
	)
	if exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, exitSuccess, stderr)
	}
	want := "Run completed\n\nTargets\n  DNS  example.com\n  DNS  example.org\n\nDNS evidence\n  example.com  A      192.0.2.10\n  example.com  A      192.0.2.20\n  example.com  AAAA   2001:db8::1\n  example.com  CNAME  edge.example.net\n  example.com  MX     10  mail.example.net\n  example.com  NS     ns.example.net\n  example.com  TXT    \"Verification=Ab C\"\n  example.org  A      198.51.100.10\n  example.org  AAAA   2001:db8::2\n  example.org  MX     20  mail.example.org\n  example.org  NS     ns.example.org\n\nDNS absence\n  example.org  CNAME  no records\n  example.org  TXT    no records\n\nCollection failures\n  none\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if len(resolver.calls) != 12 {
		t.Fatalf("resolver calls = %v, want twelve", resolver.calls)
	}
}

func TestRunDNSJSONOutputDoesNotExpandScope(t *testing.T) {
	resolver := &commandResolver{responses: map[string][]net.IP{
		"ip4:example.com": {net.ParseIP("192.0.2.10")},
		"ip6:example.com": {net.ParseIP("2001:db8::1")},
	}}
	exitCode, stdout, stderr := runReconCommand(
		context.Background(), resolver,
		"run", "--target", "example.com", "--collect", "dns", "--format", "json",
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
	}
	var result struct {
		SchemaVersion string `json:"schema_version"`
		Targets       []struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"targets"`
		Evidence []struct {
			Value string `json:"value"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is invalid JSON: %v", err)
	}
	if result.SchemaVersion != "1" || len(result.Targets) != 1 || result.Targets[0].Value != "example.com" {
		t.Fatalf("scope in JSON = %#v", result.Targets)
	}
	if len(result.Evidence) != 2 || result.Evidence[0].Value != "192.0.2.10" || result.Evidence[1].Value != "2001:db8::1" {
		t.Fatalf("evidence in JSON = %#v", result.Evidence)
	}
}

func TestRunDNSRepresentsCollectionFailure(t *testing.T) {
	resolver := &commandResolver{
		responses: map[string][]net.IP{"ip6:example.com": {net.ParseIP("2001:db8::1")}},
		errors:    map[string]error{"ip4:example.com": errors.New("resolver unavailable")},
	}
	exitCode, stdout, stderr := runReconCommand(
		context.Background(), resolver,
		"run", "--target", "example.com", "--collect", "dns", "--format", "json",
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr)
	}
	if !strings.Contains(stdout, `"status":"partial"`) || !strings.Contains(stdout, `"code":"lookup_failed"`) {
		t.Fatalf("stdout = %q, want structured partial failure", stdout)
	}
}

func TestNoResultDoesNotDegradeRunStatus(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Evidence: []model.Evidence{{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"}},
		Errors:   []model.RunError{{Code: "no_result", Target: &target, RecordType: "MX"}},
	}
	if got := runStatus(run); got != model.RunCompleted {
		t.Fatalf("runStatus() = %q, want completed", got)
	}
}

func TestEvidenceLimitDoesNotDegradeRunStatus(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	run := model.Run{
		Evidence: []model.Evidence{{Target: target, Category: "dns_record", RecordType: "TXT", Value: "retained"}},
		Errors:   []model.RunError{{Code: "evidence_limited", Target: &target, RecordType: "TXT", OmittedRecords: 1}},
	}
	if got := runStatus(run); got != model.RunCompleted {
		t.Fatalf("runStatus() = %q, want completed", got)
	}
}

func TestRunRejectsInvalidInputBeforeNetwork(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode string
		wantExit int
	}{
		{name: "missing target", args: []string{"run", "--collect", "dns"}, wantCode: "missing_target", wantExit: exitValidation},
		{name: "unsupported collector", args: []string{"run", "--target", "example.com", "--collect", "http"}, wantCode: "unsupported_collector", wantExit: exitUsage},
		{name: "missing collector", args: []string{"run", "--target", "example.com"}, wantCode: "unsupported_collector", wantExit: exitUsage},
		{name: "IP target", args: []string{"run", "--target", "192.0.2.10", "--collect", "dns"}, wantCode: "unsupported_target", wantExit: exitValidation},
		{name: "invalid target", args: []string{"run", "--target", "api..example.com", "--collect", "dns"}, wantCode: "invalid_target", wantExit: exitValidation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &commandResolver{}
			exitCode, stdout, stderr := runReconCommand(context.Background(), resolver, test.args...)
			if exitCode != test.wantExit || stdout != "" || !strings.Contains(stderr, test.wantCode) {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", exitCode, stdout, stderr)
			}
			if len(resolver.calls) != 0 {
				t.Fatalf("resolver calls = %v, want none", resolver.calls)
			}
		})
	}
}

func runCommand(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr)
	return exitCode, stdout.String(), stderr.String()
}

func runReconCommand(ctx context.Context, resolver *commandResolver, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := runContext(ctx, args, &stdout, &stderr, resolver)
	return exitCode, stdout.String(), stderr.String()
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0", exitCode)
	}
	if stdout.String() != version+"\n" {
		t.Fatalf("run() stdout = %q, want version", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"scan"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run() exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "scan"`) {
		t.Fatalf("run() stderr = %q, want unknown-command error", stderr.String())
	}
}
