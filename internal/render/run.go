package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/WH173H7/scopeforge/internal/model"
)

const runSchemaVersion = "1"

type runResult struct {
	SchemaVersion string            `json:"schema_version"`
	Status        model.RunStatus   `json:"status"`
	Targets       []outputTarget    `json:"targets"`
	Collectors    []string          `json:"collectors"`
	Evidence      []runEvidence     `json:"evidence"`
	Errors        []collectionError `json:"errors"`
}

type runEvidence struct {
	Target     outputTarget `json:"target"`
	Category   string       `json:"category"`
	RecordType string       `json:"record_type"`
	Value      string       `json:"value"`
}

type collectionError struct {
	Code       string       `json:"code"`
	Message    string       `json:"message"`
	Collector  string       `json:"collector"`
	Target     outputTarget `json:"target"`
	RecordType string       `json:"record_type"`
	Retryable  bool         `json:"retryable"`
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
			if _, err := fmt.Fprintf(output, "  %s  %-4s  %s\n", item.Target.Value, item.RecordType, item.Value); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(output, "\nCollection failures"); err != nil {
		return err
	}
	failures := orderedFailures(run.Errors)
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
		})
	}
	evidence := orderedEvidence(run.Evidence)
	outputEvidence := make([]runEvidence, 0, len(evidence))
	for _, item := range evidence {
		outputEvidence = append(outputEvidence, runEvidence{
			Target:   outputTarget{Kind: jsonKind(item.Target.Kind), Value: item.Target.Value},
			Category: item.Category, RecordType: item.RecordType, Value: item.Value,
		})
	}
	result := runResult{
		SchemaVersion: runSchemaVersion,
		Status:        run.Status,
		Targets:       outputTargets(ordered(run.Scope.Allowed)),
		Collectors:    []string{"dns"},
		Evidence:      outputEvidence,
		Errors:        errors,
	}
	return json.NewEncoder(output).Encode(result)
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
