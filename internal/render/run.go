package render

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/WH173H7/scopeforge/internal/artifact"
	"github.com/WH173H7/scopeforge/internal/model"
)

// RunText writes a deterministic human-readable reconnaissance result.
func RunText(output io.Writer, run model.Run) error {
	if _, err := fmt.Fprintf(output, "Run %s\n\nTargets\n", run.Status); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(run.Scope.Allowed)); err != nil {
		return err
	}
	return writeDNSReport(output, run)
}

// InspectText writes a deterministic human-readable saved-run inspection.
func InspectText(output io.Writer, run model.Run) error {
	finished := ""
	if run.FinishedAt != nil {
		finished = run.FinishedAt.UTC().Format(time.RFC3339Nano)
	}
	if _, err := fmt.Fprintf(output, "Saved reconnaissance run\n\nID:        %s\nStarted:   %s\nFinished:  %s\nStatus:    %s\n\nTargets\n",
		run.ID, run.StartedAt.UTC().Format(time.RFC3339Nano), finished, run.Status); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(run.Scope.Allowed)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "\nExclusions"); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(run.Scope.Excluded)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "\nCollectors"); err != nil {
		return err
	}
	collectors := run.Collectors
	if len(collectors) == 0 {
		collectors = []string{"dns"}
	}
	for _, collector := range collectors {
		if _, err := fmt.Fprintf(output, "  %s\n", collector); err != nil {
			return err
		}
	}
	return writeDNSReport(output, run)
}

func writeDNSReport(output io.Writer, run model.Run) error {
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
			failure.Target.Value, failure.RecordType, failure.Code, strconv.Quote(failure.Message),
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
	return artifact.Encode(output, run)
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
