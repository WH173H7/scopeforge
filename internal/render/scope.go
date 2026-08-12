package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/WH173H7/scopeforge/internal/model"
)

const scopeSchemaVersion = "1"

type scopeResult struct {
	SchemaVersion        string         `json:"schema_version"`
	Targets              []outputTarget `json:"targets"`
	Exclusions           []outputTarget `json:"exclusions"`
	EffectiveTargetCount int            `json:"effective_target_count"`
}

type outputTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type errorResult struct {
	Error outputError `json:"error"`
}

type outputError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScopeText writes a deterministic human-readable scope result.
func ScopeText(output io.Writer, policy model.ScopePolicy, effective []model.Target) error {
	if _, err := fmt.Fprintln(output, "Scope valid\n\nTargets"); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(policy.Allowed)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "\nExclusions"); err != nil {
		return err
	}
	if err := writeTextTargets(output, ordered(policy.Excluded)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "\nEffective targets: %d\n", len(effective))
	return err
}

// ScopeJSON writes the versioned machine-readable scope result.
func ScopeJSON(output io.Writer, policy model.ScopePolicy, effective []model.Target) error {
	result := scopeResult{
		SchemaVersion:        scopeSchemaVersion,
		Targets:              outputTargets(ordered(policy.Allowed)),
		Exclusions:           outputTargets(ordered(policy.Excluded)),
		EffectiveTargetCount: len(effective),
	}
	return json.NewEncoder(output).Encode(result)
}

func ordered(targets []model.Target) []model.Target {
	result := append([]model.Target(nil), targets...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Value < result[j].Value
	})
	return result
}

// ErrorJSON writes a stable machine-readable expected error.
func ErrorJSON(output io.Writer, code, message string) error {
	return json.NewEncoder(output).Encode(errorResult{Error: outputError{Code: code, Message: message}})
}

func writeTextTargets(output io.Writer, targets []model.Target) error {
	if len(targets) == 0 {
		_, err := fmt.Fprintln(output, "  none")
		return err
	}
	for _, target := range targets {
		if _, err := fmt.Fprintf(output, "  %-3s  %s\n", textKind(target.Kind), target.Value); err != nil {
			return err
		}
	}
	return nil
}

func outputTargets(targets []model.Target) []outputTarget {
	result := make([]outputTarget, 0, len(targets))
	for _, target := range targets {
		result = append(result, outputTarget{Kind: jsonKind(target.Kind), Value: target.Value})
	}
	return result
}

func textKind(kind model.TargetKind) string {
	if kind == model.TargetDNSName {
		return "DNS"
	}
	return "IP"
}

func jsonKind(kind model.TargetKind) string {
	if kind == model.TargetDNSName {
		return "dns"
	}
	return "ip"
}
