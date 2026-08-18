package artifact

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/WH173H7/scopeforge/internal/model"
)

// SchemaVersion is the supported persisted run artifact schema.
const SchemaVersion = "1"

// MaxBytes is the maximum artifact size inspect-run will read. It is a
// ScopeForge safety bound, not a schema constraint.
const MaxBytes = 16 << 20

// Document is the canonical schema version 1 run JSON contract shared by
// persistence, --format json, and inspect-run.
type Document struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id,omitempty"`
	StartedAt     string     `json:"started_at,omitempty"`
	FinishedAt    string     `json:"finished_at,omitempty"`
	Status        string     `json:"status"`
	Targets       []Target   `json:"targets"`
	Exclusions    []Target   `json:"exclusions"`
	Collectors    []string   `json:"collectors"`
	Evidence      []Evidence `json:"evidence"`
	Errors        []Error    `json:"errors"`
}

// Target is a JSON target object using public kind names "dns" and "ip".
type Target struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Evidence is a JSON evidence object.
type Evidence struct {
	Target         Target  `json:"target"`
	Category       string  `json:"category"`
	RecordType     string  `json:"record_type"`
	Value          string  `json:"value"`
	Priority       *uint16 `json:"priority,omitempty"`
	Encoding       string  `json:"encoding,omitempty"`
	Truncated      bool    `json:"truncated,omitempty"`
	OriginalLength *int    `json:"original_length,omitempty"`
}

// Error is a JSON collection outcome or failure object.
type Error struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	Collector      string `json:"collector"`
	Target         Target `json:"target"`
	RecordType     string `json:"record_type"`
	Retryable      bool   `json:"retryable"`
	OmittedRecords int    `json:"omitted_records,omitempty"`
	OmittedBytes   int    `json:"omitted_bytes,omitempty"`
}

// Encode writes the canonical run JSON document for run.
func Encode(output io.Writer, run model.Run) error {
	return json.NewEncoder(output).Encode(DocumentFromRun(run))
}

// DocumentFromRun maps an in-memory run onto the canonical JSON document.
func DocumentFromRun(run model.Run) Document {
	collectors := append([]string(nil), run.Collectors...)
	if len(collectors) == 0 {
		collectors = []string{"dns"}
	}
	failures := orderedFailures(run.Errors)
	errors := make([]Error, 0, len(failures))
	for _, failure := range failures {
		if failure.Target == nil {
			continue
		}
		errors = append(errors, Error{
			Code: failure.Code, Message: failure.Message, Collector: failure.Collector,
			Target: jsonTarget(*failure.Target), RecordType: failure.RecordType, Retryable: failure.Retryable,
			OmittedRecords: failure.OmittedRecords, OmittedBytes: failure.OmittedBytes,
		})
	}
	evidence := orderedEvidence(run.Evidence)
	items := make([]Evidence, 0, len(evidence))
	for _, item := range evidence {
		items = append(items, Evidence{
			Target: jsonTarget(item.Target), Category: item.Category, RecordType: item.RecordType,
			Value: item.Value, Priority: item.Priority, Encoding: item.Encoding,
			Truncated: item.Truncated, OriginalLength: item.OriginalLength,
		})
	}
	return Document{
		SchemaVersion: SchemaVersion,
		ID:            run.ID,
		StartedAt:     rfc3339UTC(run.StartedAt),
		FinishedAt:    rfc3339UTCPointer(run.FinishedAt),
		Status:        string(run.Status),
		Targets:       jsonTargets(orderedTargets(run.Scope.Allowed)),
		Exclusions:    jsonTargets(orderedTargets(run.Scope.Excluded)),
		Collectors:    collectors,
		Evidence:      items,
		Errors:        errors,
	}
}

func runFromDocument(document Document) (model.Run, error) {
	startedAt, err := parseTimestamp(document.StartedAt)
	if err != nil {
		return model.Run{}, err
	}
	finishedAt, err := parseTimestamp(document.FinishedAt)
	if err != nil {
		return model.Run{}, err
	}
	finished := finishedAt
	run := model.Run{
		ID: document.ID, StartedAt: startedAt, FinishedAt: &finished,
		Status: model.RunStatus(document.Status), Collectors: append([]string(nil), document.Collectors...),
		Scope: model.ScopePolicy{
			Allowed:  targetsFromJSON(document.Targets),
			Excluded: targetsFromJSON(document.Exclusions),
		},
		Observations: []model.Observation{},
		Evidence:     make([]model.Evidence, 0, len(document.Evidence)),
		Errors:       make([]model.RunError, 0, len(document.Errors)),
	}
	for _, item := range document.Evidence {
		run.Evidence = append(run.Evidence, model.Evidence{
			Target: modelTarget(item.Target), Category: item.Category, RecordType: item.RecordType,
			Value: item.Value, Priority: item.Priority, Encoding: item.Encoding,
			Truncated: item.Truncated, OriginalLength: item.OriginalLength,
		})
	}
	for _, item := range document.Errors {
		target := modelTarget(item.Target)
		run.Errors = append(run.Errors, model.RunError{
			Code: item.Code, Message: item.Message, Collector: item.Collector, Target: &target,
			RecordType: item.RecordType, Retryable: item.Retryable,
			OmittedRecords: item.OmittedRecords, OmittedBytes: item.OmittedBytes,
		})
	}
	return run, nil
}

func jsonTarget(target model.Target) Target {
	kind := "ip"
	if target.Kind == model.TargetDNSName {
		kind = "dns"
	}
	return Target{Kind: kind, Value: target.Value}
}

func jsonTargets(targets []model.Target) []Target {
	result := make([]Target, 0, len(targets))
	for _, target := range targets {
		result = append(result, jsonTarget(target))
	}
	return result
}

func modelTarget(target Target) model.Target {
	kind := model.TargetIP
	if target.Kind == "dns" {
		kind = model.TargetDNSName
	}
	return model.Target{Kind: kind, Value: target.Value}
}

func targetsFromJSON(targets []Target) []model.Target {
	result := make([]model.Target, 0, len(targets))
	for _, target := range targets {
		result = append(result, modelTarget(target))
	}
	return result
}

func orderedTargets(targets []model.Target) []model.Target {
	result := append([]model.Target(nil), targets...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func orderedEvidence(evidence []model.Evidence) []model.Evidence {
	result := append([]model.Evidence(nil), evidence...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Target.Value != result[j].Target.Value {
			return result[i].Target.Value < result[j].Target.Value
		}
		if result[i].RecordType != result[j].RecordType {
			return result[i].RecordType < result[j].RecordType
		}
		leftPriority, rightPriority := uint16(0), uint16(0)
		if result[i].Priority != nil {
			leftPriority = *result[i].Priority
		}
		if result[j].Priority != nil {
			rightPriority = *result[j].Priority
		}
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func orderedFailures(failures []model.RunError) []model.RunError {
	result := append([]model.RunError(nil), failures...)
	sort.Slice(result, func(i, j int) bool {
		leftTarget, rightTarget := "", ""
		if result[i].Target != nil {
			leftTarget = result[i].Target.Value
		}
		if result[j].Target != nil {
			rightTarget = result[j].Target.Value
		}
		if leftTarget != rightTarget {
			return leftTarget < rightTarget
		}
		if result[i].RecordType != result[j].RecordType {
			return result[i].RecordType < result[j].RecordType
		}
		return result[i].Code < result[j].Code
	})
	return result
}

func rfc3339UTC(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func rfc3339UTCPointer(value *time.Time) string {
	if value == nil {
		return ""
	}
	return rfc3339UTC(*value)
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	return parsed.UTC(), nil
}
