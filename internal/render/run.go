package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/WH173H7/scopeforge/internal/model"
)

const runSchemaVersion = "1"

type runResult struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id,omitempty"`
	StartedAt     string            `json:"started_at,omitempty"`
	FinishedAt    string            `json:"finished_at,omitempty"`
	Status        model.RunStatus   `json:"status"`
	Targets       []outputTarget    `json:"targets"`
	Exclusions    []outputTarget    `json:"exclusions"`
	Collectors    []string          `json:"collectors"`
	Evidence      []runEvidence     `json:"evidence"`
	Errors        []collectionError `json:"errors"`
}

type runEvidence struct {
	Target         outputTarget `json:"target"`
	Category       string       `json:"category"`
	RecordType     string       `json:"record_type"`
	Value          string       `json:"value"`
	Priority       *uint16      `json:"priority,omitempty"`
	Encoding       string       `json:"encoding,omitempty"`
	Truncated      bool         `json:"truncated,omitempty"`
	OriginalLength *int         `json:"original_length,omitempty"`
}

type collectionError struct {
	Code           string       `json:"code"`
	Message        string       `json:"message"`
	Collector      string       `json:"collector"`
	Target         outputTarget `json:"target"`
	RecordType     string       `json:"record_type"`
	Retryable      bool         `json:"retryable"`
	OmittedRecords int          `json:"omitted_records,omitempty"`
	OmittedBytes   int          `json:"omitted_bytes,omitempty"`
}

// RunText writes a deterministic human-readable reconnaissance result.
func RunText(output io.Writer, run model.Run) error {
	if _, err := fmt.Fprintf(output, "Run %s\n\nTargets\n", run.Status); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(run.Scope.Allowed)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "\nDNS evidence"); err != nil {
		return err
	}
	evidence := orderedEvidence(run.Evidence)
	if len(evidence) == 0 {
		if _, err := fmt.Fprintln(output, "  none"); err != nil {
			return err
		}
	} else {
		for _, item := range evidence {
			if item.Priority != nil {
				if _, err := fmt.Fprintf(output, "  %s  %-5s  %d  %s\n", item.Target.Value, item.RecordType, *item.Priority, item.Value); err != nil {
					return err
				}
				continue
			}
			value := item.Value
			if item.RecordType == "TXT" {
				value = strconv.Quote(value)
				if item.Encoding != "" {
					value = item.Encoding + ":" + value
				}
				if item.Truncated && item.OriginalLength != nil {
					value += fmt.Sprintf(" (truncated from %d bytes)", *item.OriginalLength)
				}
			}
			if _, err := fmt.Fprintf(output, "  %s  %-5s  %s\n", item.Target.Value, item.RecordType, value); err != nil {
				return err
			}
		}
	}

	outcomes, limits, failures := splitOutcomes(orderedFailures(run.Errors))
	if len(outcomes) != 0 {
		if _, err := fmt.Fprintln(output, "\nDNS absence"); err != nil {
			return err
		}
		for _, outcome := range outcomes {
			if _, err := fmt.Fprintf(output, "  %s  %-5s  no records\n", outcome.Target.Value, outcome.RecordType); err != nil {
				return err
			}
		}
	}
	if len(limits) != 0 {
		if _, err := fmt.Fprintln(output, "\nEvidence limits"); err != nil {
			return err
		}
		for _, limit := range limits {
			if _, err := fmt.Fprintf(output, "  %s  TXT    omitted %d records and %d bytes\n", limit.Target.Value, limit.OmittedRecords, limit.OmittedBytes); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(output, "\nCollection failures"); err != nil {
		return err
	}
	if len(failures) == 0 {
		_, err := fmt.Fprintln(output, "  none")
		return err
	}
	for _, failure := range failures {
		if _, err := fmt.Fprintf(
			output, "  %s  %-4s  %s: %s\n",
			failure.Target.Value, failure.RecordType, failure.Code, failure.Message,
		); err != nil {
			return err
		}
	}
	return nil
}

func splitOutcomes(results []model.RunError) ([]model.RunError, []model.RunError, []model.RunError) {
	outcomes := make([]model.RunError, 0)
	limits := make([]model.RunError, 0)
	failures := make([]model.RunError, 0)
	for _, result := range results {
		if result.Code == "no_result" {
			outcomes = append(outcomes, result)
			continue
		}
		if result.Code == "evidence_limited" {
			limits = append(limits, result)
			continue
		}
		failures = append(failures, result)
	}
	return outcomes, limits, failures
}

// RunJSON writes the versioned machine-readable reconnaissance result.
func RunJSON(output io.Writer, run model.Run) error {
	failures := orderedFailures(run.Errors)
	errors := make([]collectionError, 0, len(failures))
	for _, failure := range failures {
		if failure.Target == nil {
			continue
		}
		errors = append(errors, collectionError{
			Code: failure.Code, Message: failure.Message, Collector: failure.Collector,
			Target:     outputTarget{Kind: jsonKind(failure.Target.Kind), Value: failure.Target.Value},
			RecordType: failure.RecordType, Retryable: failure.Retryable,
			OmittedRecords: failure.OmittedRecords, OmittedBytes: failure.OmittedBytes,
		})
	}
	evidence := orderedEvidence(run.Evidence)
	outputEvidence := make([]runEvidence, 0, len(evidence))
	for _, item := range evidence {
		outputEvidence = append(outputEvidence, runEvidence{
			Target:   outputTarget{Kind: jsonKind(item.Target.Kind), Value: item.Target.Value},
			Category: item.Category, RecordType: item.RecordType, Value: item.Value, Priority: item.Priority,
			Encoding: item.Encoding, Truncated: item.Truncated, OriginalLength: item.OriginalLength,
		})
	}
	result := runResult{
		SchemaVersion: runSchemaVersion,
		ID:            run.ID,
		StartedAt:     rfc3339UTC(run.StartedAt),
		FinishedAt:    rfc3339UTCPointer(run.FinishedAt),
		Status:        run.Status,
		Targets:       outputTargets(ordered(run.Scope.Allowed)),
		Exclusions:    outputTargets(ordered(run.Scope.Excluded)),
		Collectors:    []string{"dns"},
		Evidence:      outputEvidence,
		Errors:        errors,
	}
	return json.NewEncoder(output).Encode(result)
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
