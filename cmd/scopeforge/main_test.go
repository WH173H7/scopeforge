package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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

func runCommand(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	exitCode := run(args, &stdout, &stderr)
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
