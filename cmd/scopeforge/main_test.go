package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WH173H7/scopeforge/internal/artifact"
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
		"example.com": {"Verification=Ab C", "café"}, "example.org": {},
	}}
	exitCode, stdout, stderr := runReconCommand(
		context.Background(), resolver,
		"run", "--target", "example.org", "--target", "example.com", "--collect", "dns",
	)
	if exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, exitSuccess, stderr)
	}
	want := "Run completed\n\nTargets\n  DNS  example.com\n  DNS  example.org\n\nDNS evidence\n  example.com  A      192.0.2.10\n  example.com  A      192.0.2.20\n  example.com  AAAA   2001:db8::1\n  example.com  CNAME  edge.example.net\n  example.com  MX     10  mail.example.net\n  example.com  NS     ns.example.net\n  example.com  TXT    \"Verification=Ab C\"\n  example.com  TXT    \"café\"\n  example.org  A      198.51.100.10\n  example.org  AAAA   2001:db8::2\n  example.org  MX     20  mail.example.org\n  example.org  NS     ns.example.org\n\nDNS absence\n  example.org  CNAME  no records\n  example.org  TXT    no records\n\nCollection failures\n  none\n"
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
	}, txt: map[string][]string{
		"example.com": {"café"},
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
			RecordType string `json:"record_type"`
			Value      string `json:"value"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is invalid JSON: %v", err)
	}
	if result.SchemaVersion != "1" || len(result.Targets) != 1 || result.Targets[0].Value != "example.com" {
		t.Fatalf("scope in JSON = %#v", result.Targets)
	}
	if len(result.Evidence) != 3 || result.Evidence[0].Value != "192.0.2.10" || result.Evidence[1].Value != "2001:db8::1" {
		t.Fatalf("evidence in JSON = %#v", result.Evidence)
	}
	if result.Evidence[2].RecordType != "TXT" || result.Evidence[2].Value != "café" {
		t.Fatalf("TXT JSON evidence = %#v", result.Evidence[2])
	}
	if strings.Contains(stdout, `\u00e9`) {
		t.Fatalf("JSON used ASCII escapes for printable TXT Unicode: %q", stdout)
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

func TestRunWithoutSaveDirWritesNoArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	resolver := dnsResolver()
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), fixedRunEnv(resolver),
		"run", "--target", "example.com", "--collect", "dns",
	)
	if exitCode != exitSuccess || stderr != "" || stdout == "" {
		t.Fatalf("exit = %d stdout = %q stderr = %q", exitCode, stdout, stderr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected files without --save-dir: %v", entries)
	}
}

func TestRunSaveDirWritesOneCanonicalArtifact(t *testing.T) {
	dir := t.TempDir()
	resolver := dnsResolver()
	env := fixedRunEnv(resolver)
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), env,
		"run", "--target", "example.com", "--collect", "dns", "--save-dir", dir,
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("exit = %d stderr = %q", exitCode, stderr)
	}

	_, withoutSave, withoutErr := runReconCommandEnv(
		context.Background(), fixedRunEnv(dnsResolver()),
		"run", "--target", "example.com", "--collect", "dns",
	)
	if withoutErr != "" || stdout != withoutSave {
		t.Fatalf("stdout changed when --save-dir was added")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "20260818T150405Z-abababababababab.json" {
		t.Fatalf("artifacts = %v", entries)
	}
	if strings.Contains(entries[0].Name(), "example.com") {
		t.Fatal("artifact filename included a target name")
	}

	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		SchemaVersion string `json:"schema_version"`
		ID            string `json:"id"`
		StartedAt     string `json:"started_at"`
		FinishedAt    string `json:"finished_at"`
		Status        string `json:"status"`
		Collectors    []string
		Targets       []struct{ Value string }
		Evidence      []struct {
			RecordType string `json:"record_type"`
			Value      string `json:"value"`
		}
		Errors []struct{ Code string }
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("artifact JSON: %v", err)
	}
	if document.SchemaVersion != "1" || document.ID != "20260818T150405Z-abababababababab" {
		t.Fatalf("identity = %#v", document)
	}
	if document.StartedAt != "2026-08-18T15:04:05Z" || document.FinishedAt != "2026-08-18T15:04:06Z" {
		t.Fatalf("timestamps = %#v", document)
	}
	if document.Status != "completed" || len(document.Collectors) != 1 || document.Collectors[0] != "dns" {
		t.Fatalf("run metadata = %#v", document)
	}
	if len(document.Targets) != 1 || document.Targets[0].Value != "example.com" {
		t.Fatalf("targets = %#v", document.Targets)
	}
	if len(document.Evidence) < 3 {
		t.Fatalf("evidence = %#v", document.Evidence)
	}
}

func TestRunSaveDirJSONStdoutRemainsValidAndDoesNotCallResolverAgain(t *testing.T) {
	dir := t.TempDir()
	resolver := dnsResolver()
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), fixedRunEnv(resolver),
		"run", "--target", "example.com", "--collect", "dns", "--format", "json", "--save-dir", dir,
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("exit = %d stderr = %q", exitCode, stderr)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("stdout JSON: %v body = %q", err, stdout)
	}
	if document["id"] != "20260818T150405Z-abababababababab" {
		t.Fatalf("stdout id = %#v", document["id"])
	}
	body, err := os.ReadFile(filepath.Join(dir, "20260818T150405Z-abababababababab.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(body) {
		t.Fatalf("stdout JSON did not match artifact")
	}
	if len(resolver.calls) != 6 {
		t.Fatalf("resolver calls = %v, want six collection lookups", resolver.calls)
	}
}

func TestRunSaveDirDoesNotOverwriteExistingArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "20260818T150405Z-abababababababab.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := dnsResolver()
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), fixedRunEnv(resolver),
		"run", "--target", "example.com", "--collect", "dns", "--format", "json", "--save-dir", dir,
	)
	if exitCode != exitInternal || !strings.Contains(stderr, "artifact_write_failed") {
		t.Fatalf("exit = %d stderr = %q", exitCode, stderr)
	}
	if !json.Valid([]byte(stdout)) || strings.Contains(stdout, "artifact_write_failed") {
		t.Fatalf("JSON stdout polluted: %q", stdout)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep" {
		t.Fatalf("existing artifact overwritten: %q", body)
	}
}

func TestRunSaveDirFailureDoesNotPolluteJSONStdout(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), fixedRunEnv(dnsResolver()),
		"run", "--target", "example.com", "--collect", "dns", "--format", "json", "--save-dir", blocked,
	)
	if exitCode != exitInternal || !strings.Contains(stderr, "artifact_write_failed") {
		t.Fatalf("exit = %d stderr = %q", exitCode, stderr)
	}
	if !json.Valid([]byte(stdout)) || strings.Contains(stdout, "artifact_write_failed") {
		t.Fatalf("JSON stdout polluted: %q", stdout)
	}
	if strings.Contains(stderr, "café") || strings.Contains(stderr, "192.0.2.10") {
		t.Fatalf("stderr duplicated evidence: %q", stderr)
	}
}

func TestInspectRunTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	env := fixedRunEnv(dnsResolver())
	exitCode, _, stderr := runReconCommandEnv(
		context.Background(), env,
		"run", "--target", "example.com", "--collect", "dns", "--save-dir", dir,
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("save exit = %d stderr = %q", exitCode, stderr)
	}
	id := "20260818T150405Z-abababababababab"
	path := filepath.Join(dir, id+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	resolver := &commandResolver{}
	exitCode, stdout, stderr := runReconCommandEnv(
		context.Background(), defaultEnv(resolver),
		"inspect-run", "--run-dir", dir, "--id", id,
	)
	if exitCode != exitSuccess || stderr != "" {
		t.Fatalf("inspect text exit = %d stderr = %q", exitCode, stderr)
	}
	if !strings.Contains(stdout, "Saved reconnaissance run") || !strings.Contains(stdout, id) {
		t.Fatalf("text stdout = %q", stdout)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("inspect-run made resolver calls: %v", resolver.calls)
	}

	exitCode, jsonOut, stderr := runReconCommandEnv(
		context.Background(), defaultEnv(resolver),
		"inspect-run", "--run-dir", dir, "--id", id, "--format", "json",
	)
	if exitCode != exitSuccess || stderr != "" || !json.Valid([]byte(jsonOut)) {
		t.Fatalf("inspect json exit = %d stderr = %q stdout = %q", exitCode, stderr, jsonOut)
	}
	if jsonOut != string(before) {
		t.Fatalf("JSON inspect did not match saved artifact")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("inspect-run modified artifact bytes")
	}
}

func TestInspectRunExpectedErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name     string
		args     []string
		wantCode string
		wantExit int
	}{
		{name: "missing run dir", args: []string{"inspect-run", "--id", "20260818T150405Z-abababababababab"}, wantCode: "missing_run_dir", wantExit: exitValidation},
		{name: "missing id", args: []string{"inspect-run", "--run-dir", dir}, wantCode: "missing_run_id", wantExit: exitValidation},
		{name: "path traversal id", args: []string{"inspect-run", "--run-dir", dir, "--id", "../secret"}, wantCode: "invalid_run_id", wantExit: exitValidation},
		{name: "not found", args: []string{"inspect-run", "--run-dir", dir, "--id", "20260818T150405Z-abababababababab"}, wantCode: "artifact_not_found", wantExit: exitValidation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &commandResolver{}
			exitCode, stdout, stderr := runReconCommandEnv(context.Background(), defaultEnv(resolver), test.args...)
			if exitCode != test.wantExit || stdout != "" || !strings.Contains(stderr, test.wantCode) {
				t.Fatalf("exit = %d stdout = %q stderr = %q", exitCode, stdout, stderr)
			}
			if len(resolver.calls) != 0 {
				t.Fatalf("resolver calls = %v", resolver.calls)
			}
		})
	}
}

func TestInspectRunJSONErrorUsesStdoutOnly(t *testing.T) {
	exitCode, stdout, stderr := runCommand(
		"inspect-run", "--run-dir", t.TempDir(), "--id", "20260818T150405Z-abababababababab", "--format", "json",
	)
	if exitCode != exitValidation || stderr != "" {
		t.Fatalf("exit = %d stderr = %q", exitCode, stderr)
	}
	if !json.Valid([]byte(stdout)) || !strings.Contains(stdout, "artifact_not_found") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func runCommand(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr)
	return exitCode, stdout.String(), stderr.String()
}

func runReconCommand(ctx context.Context, resolver *commandResolver, args ...string) (int, string, string) {
	return runReconCommandEnv(ctx, defaultEnv(resolver), args...)
}

func runReconCommandEnv(ctx context.Context, env runEnv, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := runContext(ctx, args, &stdout, &stderr, env)
	return exitCode, stdout.String(), stderr.String()
}

func fixedRunEnv(resolver *commandResolver) runEnv {
	started := time.Date(2026, 8, 18, 15, 4, 5, 0, time.UTC)
	calls := 0
	return runEnv{
		resolver: resolver,
		now: func() time.Time {
			defer func() { calls++ }()
			return started.Add(time.Duration(calls) * time.Second)
		},
		newID: func(now time.Time) (string, error) {
			return artifact.NewID(now, bytes.NewReader(bytes.Repeat([]byte{0xab}, 8)))
		},
	}
}

func dnsResolver() *commandResolver {
	return &commandResolver{responses: map[string][]net.IP{
		"ip4:example.com": {net.ParseIP("192.0.2.10")},
		"ip6:example.com": {net.ParseIP("2001:db8::1")},
	}, txt: map[string][]string{
		"example.com": {"café"},
	}}
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
