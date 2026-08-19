package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/WH173H7/scopeforge/internal/model"
)

func TestReadRoundTripValidArtifact(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	if err := Write(dir, run); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(dir, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != run.ID || loaded.Status != run.Status || loaded.Collectors[0] != "dns" {
		t.Fatalf("loaded identity = %#v", loaded)
	}
	if loaded.StartedAt.UTC().Format("2006-01-02T15:04:05Z") != "2026-08-18T15:04:05Z" {
		t.Fatalf("started = %v", loaded.StartedAt)
	}
	if loaded.FinishedAt == nil || loaded.FinishedAt.Before(loaded.StartedAt) {
		t.Fatalf("finished = %v", loaded.FinishedAt)
	}
	if len(loaded.Scope.Allowed) != 1 || loaded.Scope.Allowed[0].Value != "example.com" {
		t.Fatalf("targets = %#v", loaded.Scope.Allowed)
	}
	if len(loaded.Evidence) != 2 || loaded.Evidence[1].Encoding != "base64" || !loaded.Evidence[1].Truncated {
		t.Fatalf("evidence = %#v", loaded.Evidence)
	}
	codes := map[string]struct{}{}
	for _, item := range loaded.Errors {
		codes[item.Code] = struct{}{}
	}
	for _, code := range []string{"no_result", "evidence_limited", "lookup_failed"} {
		if _, ok := codes[code]; !ok {
			t.Fatalf("missing %s", code)
		}
	}
}

func TestReadRejectsPathTraversalAndAbsoluteIDs(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"../secret", "/tmp/scopeforge", `C:foo`, "foo/bar", "foo.json"} {
		if _, err := Read(dir, id); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("id %q error = %v, want ErrInvalidID", id, err)
		}
	}
}

func TestReadMissingArtifact(t *testing.T) {
	_, err := Read(t.TempDir(), sampleRun().ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read() error = %v, want ErrNotFound", err)
	}
}

func TestReadRejectsIDMismatch(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	if err := Write(dir, run); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, run.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	otherID := "20260818T150405Z-cccccccccccccccc"
	if err := os.WriteFile(filepath.Join(dir, otherID+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, otherID); !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("Read() error = %v, want ErrIDMismatch", err)
	}
}

func TestReadToleratesUnknownAdditiveField(t *testing.T) {
	dir := t.TempDir()
	document := mutateSampleJSON(t, func(raw map[string]any) {
		raw["future_note"] = "ignored"
	})
	writeJSON(t, dir, sampleRun().ID, document)
	if _, err := Read(dir, sampleRun().ID); err != nil {
		t.Fatalf("unknown additive field rejected: %v", err)
	}
}

func TestReadValidationFailures(t *testing.T) {
	id := sampleRun().ID
	tests := []struct {
		name string
		want error
		edit func(map[string]any)
	}{
		{name: "malformed JSON wrapper", want: ErrInvalid, edit: nil},
		{name: "missing schema", want: ErrUnsupportedSchema, edit: func(raw map[string]any) { delete(raw, "schema_version") }},
		{name: "unsupported schema", want: ErrUnsupportedSchema, edit: func(raw map[string]any) { raw["schema_version"] = "2" }},
		{name: "missing id", want: ErrInvalid, edit: func(raw map[string]any) { delete(raw, "id") }},
		{name: "invalid internal id", want: ErrInvalid, edit: func(raw map[string]any) { raw["id"] = "../x" }},
		{name: "invalid started_at", want: ErrInvalid, edit: func(raw map[string]any) { raw["started_at"] = "not-a-time" }},
		{name: "invalid finished_at", want: ErrInvalid, edit: func(raw map[string]any) { raw["finished_at"] = "also-bad" }},
		{name: "finished before started", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["started_at"] = "2026-08-18T15:04:07Z"
			raw["finished_at"] = "2026-08-18T15:04:05Z"
		}},
		{name: "unknown status", want: ErrInvalid, edit: func(raw map[string]any) { raw["status"] = "exploded" }},
		{name: "malformed target", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["targets"] = []any{map[string]any{"kind": "dns", "value": "edge..example.com"}}
		}},
		{name: "malformed exclusion", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["exclusions"] = []any{map[string]any{"kind": "dns", "value": "*.example.com"}}
		}},
		{name: "unknown collector", want: ErrInvalid, edit: func(raw map[string]any) { raw["collectors"] = []any{"http"} }},
		{name: "malformed evidence", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "SRV", "value": "x"}}
		}},
		{name: "malformed TXT encoding", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "TXT", "value": "x", "encoding": "hex"}}
		}},
		{name: "empty targets", want: ErrInvalid, edit: func(raw map[string]any) { raw["targets"] = []any{} }},
		{name: "CNAME control characters", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "CNAME", "value": "edge\x1b.example.com"}}
		}},
		{name: "NS control characters", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "NS", "value": "ns\n.example.com"}}
		}},
		{name: "MX control characters", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "MX", "value": "mail\r.example.com", "priority": 10}}
		}},
		{name: "unknown outcome code", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["errors"] = []any{map[string]any{"code": "owned", "message": "x", "collector": "dns", "target": map[string]any{"kind": "dns", "value": "example.com"}, "record_type": "A"}}
		}},
		{name: "unknown outcome record type", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["errors"] = []any{map[string]any{"code": "lookup_failed", "message": "x", "collector": "dns", "target": map[string]any{"kind": "dns", "value": "example.com"}, "record_type": "SRV"}}
		}},
		{name: "evidence target outside scope", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "other.example"}, "category": "dns_record", "record_type": "A", "value": "192.0.2.10"}}
		}},
		{name: "outcome target outside scope", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["errors"] = []any{map[string]any{"code": "no_result", "message": "DNS lookup returned no records", "collector": "dns", "target": map[string]any{"kind": "dns", "value": "other.example"}, "record_type": "MX"}}
		}},
		{name: "excluded target evidence", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["exclusions"] = []any{map[string]any{"kind": "dns", "value": "example.com"}}
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "A", "value": "192.0.2.10"}}
		}},
		{name: "A record TXT encoding metadata", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "A", "value": "192.0.2.10", "encoding": "base64"}}
		}},
		{name: "NS record TXT truncation metadata", want: ErrInvalid, edit: func(raw map[string]any) {
			raw["evidence"] = []any{map[string]any{"target": map[string]any{"kind": "dns", "value": "example.com"}, "category": "dns_record", "record_type": "NS", "value": "ns.example.com", "truncated": true, "original_length": 12}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.edit == nil {
				if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				writeJSON(t, dir, id, mutateSampleJSON(t, test.edit))
			}
			_, err := Read(dir, id)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReadPreservesUnicodeTXT(t *testing.T) {
	dir := t.TempDir()
	document := mutateSampleJSON(t, func(raw map[string]any) {
		raw["evidence"] = []any{map[string]any{
			"target":   map[string]any{"kind": "dns", "value": "example.com"},
			"category": "dns_record", "record_type": "TXT", "value": "café",
		}}
	})
	writeJSON(t, dir, sampleRun().ID, document)
	loaded, err := Read(dir, sampleRun().ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Evidence) != 1 || loaded.Evidence[0].Value != "café" {
		t.Fatalf("evidence = %#v", loaded.Evidence)
	}
}

func TestReadPreservesNullMXAndTXTMetadata(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	priority := uint16(0)
	run.Evidence = append(run.Evidence, modelEvidenceMX(priority))
	if err := Write(dir, run); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(dir, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var sawNullMX, sawTXT bool
	for _, item := range loaded.Evidence {
		if item.RecordType == "MX" && item.Value == "." && item.Priority != nil && *item.Priority == 0 {
			sawNullMX = true
		}
		if item.RecordType == "TXT" && item.Encoding == "base64" && item.Truncated && item.OriginalLength != nil {
			sawTXT = true
		}
	}
	if !sawNullMX || !sawTXT {
		t.Fatalf("evidence = %#v", loaded.Evidence)
	}
}

func TestReadOversizedArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sampleRun().ID+".json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, sampleRun().ID); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}

func TestReadRejectsSymlinkArtifact(t *testing.T) {
	dir := t.TempDir()
	id := sampleRun().ID
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, id+".json")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks are not available")
		}
		t.Fatal(err)
	}
	if _, err := Read(dir, id); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink error = %v, want ErrInvalid", err)
	}
}

func TestReadDoesNotModifyArtifactBytes(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun()
	if err := Write(dir, run); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, run.ID+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, run.ID); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("artifact bytes changed after Read")
	}
}

func mutateSampleJSON(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := Encode(&encoded, sampleRun()); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	edit(raw)
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func writeJSON(t *testing.T, dir, id string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, id+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func modelEvidenceMX(priority uint16) model.Evidence {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	pref := priority
	return model.Evidence{Target: target, Category: "dns_record", RecordType: "MX", Value: ".", Priority: &pref}
}
