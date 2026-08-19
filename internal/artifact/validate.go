package artifact

import (
	"encoding/base64"
	"net/netip"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/scope"
)

var knownStatuses = map[model.RunStatus]struct{}{
	model.RunPending:   {},
	model.RunRunning:   {},
	model.RunCompleted: {},
	model.RunPartial:   {},
	model.RunFailed:    {},
	model.RunCanceled:  {},
}

var knownRecordTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "MX": {}, "NS": {}, "CNAME": {}, "TXT": {},
}

var knownOutcomeCodes = map[string]struct{}{
	"no_result":        {},
	"evidence_limited": {},
	"lookup_failed":    {},
	"timeout":          {},
	"canceled":         {},
}

func validateDocument(document Document, requestedID string) error {
	if document.SchemaVersion != SchemaVersion {
		return ErrUnsupportedSchema
	}
	if document.ID == "" || !ValidID(document.ID) {
		return ErrInvalid
	}
	if document.ID != requestedID {
		return ErrIDMismatch
	}
	if document.StartedAt == "" || document.FinishedAt == "" {
		return ErrInvalid
	}
	startedAt, err := parseTimestamp(document.StartedAt)
	if err != nil {
		return ErrInvalid
	}
	finishedAt, err := parseTimestamp(document.FinishedAt)
	if err != nil {
		return ErrInvalid
	}
	if finishedAt.Before(startedAt) {
		return ErrInvalid
	}
	if _, ok := knownStatuses[model.RunStatus(document.Status)]; !ok {
		return ErrInvalid
	}
	if err := validateAllowedTargets(document.Targets); err != nil {
		return err
	}
	if err := validateTargets(document.Exclusions); err != nil {
		return err
	}
	if err := validateCollectors(document.Collectors); err != nil {
		return err
	}

	allowed := targetsFromJSON(document.Targets)
	excluded := targetsFromJSON(document.Exclusions)
	for _, item := range document.Evidence {
		if err := validateEvidence(item); err != nil {
			return err
		}
		if err := validateScopeTarget(modelTarget(item.Target), allowed, excluded); err != nil {
			return err
		}
	}
	for _, item := range document.Errors {
		if err := validateOutcome(item); err != nil {
			return err
		}
		if err := validateScopeTarget(modelTarget(item.Target), allowed, excluded); err != nil {
			return err
		}
	}
	return nil
}

func validateAllowedTargets(targets []Target) error {
	if len(targets) == 0 {
		return ErrInvalid
	}
	return validateTargets(targets)
}

func validateTargets(targets []Target) error {
	if targets == nil {
		return ErrInvalid
	}
	for _, target := range targets {
		if err := validateTarget(target); err != nil {
			return err
		}
	}
	return nil
}

func validateTarget(target Target) error {
	if target.Kind != "dns" && target.Kind != "ip" {
		return ErrInvalid
	}
	parsed, err := scope.ParseTarget(target.Value)
	if err != nil {
		return ErrInvalid
	}
	if parsed.Value != target.Value {
		return ErrInvalid
	}
	if target.Kind == "dns" && parsed.Kind != model.TargetDNSName {
		return ErrInvalid
	}
	if target.Kind == "ip" && parsed.Kind != model.TargetIP {
		return ErrInvalid
	}
	return nil
}

func validateScopeTarget(target model.Target, allowed, excluded []model.Target) error {
	if targetInList(excluded, target) {
		return ErrInvalid
	}
	if !targetInList(allowed, target) {
		return ErrInvalid
	}
	return nil
}

func targetInList(list []model.Target, target model.Target) bool {
	for _, candidate := range list {
		if candidate == target {
			return true
		}
	}
	return false
}

func validateCollectors(collectors []string) error {
	if len(collectors) == 0 {
		return ErrInvalid
	}
	for _, collector := range collectors {
		if collector != "dns" {
			return ErrInvalid
		}
	}
	return nil
}

func validateEvidence(item Evidence) error {
	if err := validateTarget(item.Target); err != nil {
		return err
	}
	if item.Category != "dns_record" {
		return ErrInvalid
	}
	if _, ok := knownRecordTypes[item.RecordType]; !ok {
		return ErrInvalid
	}
	if item.RecordType != "TXT" {
		if item.Encoding != "" || item.Truncated || item.OriginalLength != nil {
			return ErrInvalid
		}
	} else {
		if item.Encoding != "" && item.Encoding != "base64" {
			return ErrInvalid
		}
		if item.Truncated {
			if item.OriginalLength == nil || *item.OriginalLength < 0 {
				return ErrInvalid
			}
		} else if item.OriginalLength != nil {
			return ErrInvalid
		}
		if item.Encoding == "base64" {
			if _, err := base64.StdEncoding.DecodeString(item.Value); err != nil {
				return ErrInvalid
			}
		}
	}
	switch item.RecordType {
	case "MX":
		if item.Priority == nil {
			return ErrInvalid
		}
		return validateMXValue(item.Value)
	case "A", "AAAA":
		if item.Priority != nil {
			return ErrInvalid
		}
		parsed, err := netip.ParseAddr(item.Value)
		if err != nil {
			return ErrInvalid
		}
		if item.RecordType == "A" && !parsed.Is4() {
			return ErrInvalid
		}
		if item.RecordType == "AAAA" && !parsed.Is6() {
			return ErrInvalid
		}
		if parsed.String() != item.Value {
			return ErrInvalid
		}
	case "TXT":
		if item.Priority != nil {
			return ErrInvalid
		}
	case "CNAME", "NS":
		if item.Priority != nil {
			return ErrInvalid
		}
		return validateDNSHostname(item.Value)
	default:
		return ErrInvalid
	}
	return nil
}

func validateMXValue(value string) error {
	if value == "." {
		return nil
	}
	return validateDNSHostname(value)
}

func validateDNSHostname(value string) error {
	parsed, err := scope.ParseTarget(value)
	if err != nil || parsed.Kind != model.TargetDNSName {
		return ErrInvalid
	}
	if parsed.Value != value {
		return ErrInvalid
	}
	return nil
}

func validateOutcome(item Error) error {
	if item.Code == "" || item.Message == "" || item.Collector == "" || item.RecordType == "" {
		return ErrInvalid
	}
	if item.Collector != "dns" {
		return ErrInvalid
	}
	if _, ok := knownOutcomeCodes[item.Code]; !ok {
		return ErrInvalid
	}
	if _, ok := knownRecordTypes[item.RecordType]; !ok {
		return ErrInvalid
	}
	return validateTarget(item.Target)
}
