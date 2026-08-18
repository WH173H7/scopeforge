package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/render"
)

func TestNewIDIsFilesystemSafeAndDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 18, 15, 4, 5, 123, time.UTC)
	id, err := NewID(now, bytes.NewReader(bytes.Repeat([]byte{0xab}, randomIDBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if id != "20260818T150405Z-abababababababab" {
		t.Fatalf("NewID() = %q", id)
	}
	if !validID(id) || strings.Contains(id, "example.com") {
		t.Fatalf("unsafe ID %q", id)
	}
}

func TestNewIDFailsWhenRandomSourceEnds(t *testing.T) {
	_, err := NewID(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), bytes.NewReader(nil))
	if err == nil {
		t.Fatal("NewID() succeeded with an empty random source")
	}
}

func TestWriteCreatesOwnerOnlyJSONArtifact(t *testing.T) {
	dir := t.TempDir()
	saveDir := filepath.Join(dir, "runs")
	run := sampleRun()

	if err := Write(saveDir, run); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(saveDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != run.ID+".json" {
		t.Fatalf("artifact names = %v, want %s.json", names(entries), run.ID)
	}
	if strings.Contains(entries[0].Name(), "example.com") {
		t.Fatal("artifact filename included a target name")
	}

	body, err := os.ReadFile(filepath.Join(saveDir, run.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := render.RunJSON(&encoded, run); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, encoded.Bytes()) {
		t.Fatalf("artifact JSON = %s, want canonical %s", body, encoded.Bytes())
	}

	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("artifact is invalid JSON: %v", err)
	}
	if document["schema_version"] != "1" || document["id"] != run.ID {
		t.Fatalf("identity = %#v", document)
	}
	if document["started_at"] != "2026-08-18T15:04:05Z" || document["finished_at"] != "2026-08-18T15:04:07Z" {
		t.Fatalf("timestamps = %#v", document)
	}
	if document["status"] != "completed" {
		t.Fatalf("status = %#v", document["status"])
	}
	collectors, _ := document["collectors"].([]any)
	if len(collectors) != 1 || collectors[0] != "dns" {
		t.Fatalf("collectors = %#v", document["collectors"])
	}

	if runtime.GOOS == "windows" {
		return
	}
	dirInfo, err := os.Stat(saveDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != dirPermission {
		t.Fatalf("directory mode = %o, want %o", dirInfo.Mode().Perm(), dirPermission)
	}
	fileInfo, err := os.Stat(filepath.Join(saveDir, run.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != filePermission {
		t.Fatalf("file mode = %o, want %o", fileInfo.Mode().Perm(), filePermission)
	}
}

func TestWritePreservesEvidenceOutcomesAndErrors(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	if err := Write(dir, run); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, run.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Targets    []struct{ Value string } `json:"targets"`
		Exclusions []struct{ Value string } `json:"exclusions"`
		Evidence   []struct {
			RecordType     string `json:"record_type"`
			Value          string `json:"value"`
			Encoding       string `json:"encoding"`
			Truncated      bool   `json:"truncated"`
			OriginalLength int    `json:"original_length"`
		} `json:"evidence"`
		Errors []struct {
			Code           string `json:"code"`
			OmittedRecords int    `json:"omitted_records"`
			OmittedBytes   int    `json:"omitted_bytes"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Targets) != 1 || document.Targets[0].Value != "example.com" {
		t.Fatalf("targets = %#v", document.Targets)
	}
	if len(document.Exclusions) != 1 || document.Exclusions[0].Value != "ignored.example" {
		t.Fatalf("exclusions = %#v", document.Exclusions)
	}
	if len(document.Evidence) != 2 || document.Evidence[0].Value != "192.0.2.10" {
		t.Fatalf("evidence = %#v", document.Evidence)
	}
	txt := document.Evidence[1]
	if txt.RecordType != "TXT" || txt.Encoding != "base64" || !txt.Truncated || txt.OriginalLength != 5000 {
		t.Fatalf("TXT evidence = %#v", txt)
	}
	codes := map[string]struct{}{}
	for _, item := range document.Errors {
		codes[item.Code] = struct{}{}
		if item.Code == "evidence_limited" && (item.OmittedRecords != 1 || item.OmittedBytes != 80) {
			t.Fatalf("evidence_limited = %#v", item)
		}
	}
	for _, code := range []string{"no_result", "evidence_limited", "lookup_failed"} {
		if _, ok := codes[code]; !ok {
			t.Fatalf("missing %s in %#v", code, document.Errors)
		}
	}
}

func TestWriteDoesNotOverwriteExistingArtifact(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	path := filepath.Join(dir, run.ID+".json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, run); !errors.Is(err, ErrExists) {
		t.Fatalf("Write() error = %v, want ErrExists", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep" {
		t.Fatalf("existing artifact overwritten: %q", body)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestWriteRejectsInvalidIDAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	run.ID = "../example.com"
	if err := Write(dir, run); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("Write() error = %v, want ErrInvalidID", err)
	}
	assertNoTemporaryFiles(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected files: %v", names(entries))
	}
}

func TestWriteCleansTemporaryFileOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not Unix-like")
	}
	dir := t.TempDir()
	run := sampleRun()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := Write(dir, run); err == nil {
		t.Fatal("Write() succeeded in a read-only directory")
	}
	assertNoTemporaryFiles(t, dir)
}

func TestWriteDoesNotChmodExistingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not Unix-like")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, sampleRun()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("existing directory mode = %o, want 0755", info.Mode().Perm())
	}
}

func sampleRun() model.Run {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	started := time.Date(2026, 8, 18, 15, 4, 5, 0, time.UTC)
	finished := started.Add(2 * time.Second)
	originalLength := 5000
	return model.Run{
		ID: "20260818T150405Z-abababababababab", StartedAt: started, FinishedAt: &finished,
		Status: model.RunCompleted,
		Scope: model.ScopePolicy{
			Allowed:  []model.Target{target},
			Excluded: []model.Target{{Kind: model.TargetDNSName, Value: "ignored.example"}},
		},
		Evidence: []model.Evidence{
			{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
			{
				Target: target, Category: "dns_record", RecordType: "TXT", Value: "YWJj",
				Encoding: "base64", Truncated: true, OriginalLength: &originalLength,
			},
		},
		Errors: []model.RunError{
			{Code: "no_result", Message: "DNS lookup returned no records", Collector: "dns", Target: &target, RecordType: "CNAME"},
			{Code: "evidence_limited", Message: "TXT evidence exceeded retention limits", Collector: "dns", Target: &target, RecordType: "TXT", OmittedRecords: 1, OmittedBytes: 80},
			{Code: "lookup_failed", Message: "DNS lookup failed", Collector: "dns", Target: &target, RecordType: "AAAA", Retryable: true},
		},
	}
}

func names(entries []os.DirEntry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Name())
	}
	return result
}

func assertNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") || strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}
