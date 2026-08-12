package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/WH173H7/scopeforge/internal/model"
)

var (
	ErrEmptyTarget   = errors.New("target is empty")
	ErrInvalidTarget = errors.New("target is not a valid DNS name or IP address")
)

// InputError identifies which scope input list contains an invalid target.
type InputError struct {
	exclusion bool
	index     int
	err       error
}

func (err *InputError) Error() string {
	listName := "allowed"
	if err.exclusion {
		listName = "excluded"
	}
	return fmt.Sprintf("%s target %d: %v", listName, err.index, err.err)
}

func (err *InputError) Unwrap() error {
	return err.err
}

// IsExclusion reports whether the invalid input came from the exclusion list.
func (err *InputError) IsExclusion() bool {
	return err.exclusion
}

// ParseTarget validates and normalizes an exact DNS name or IP address.
func ParseTarget(value string) (model.Target, error) {
	if value == "" {
		return model.Target{}, ErrEmptyTarget
	}
	if strings.TrimSpace(value) != value {
		return model.Target{}, fmt.Errorf("%w: surrounding whitespace", ErrInvalidTarget)
	}

	if address, err := netip.ParseAddr(value); err == nil {
		return model.Target{Kind: model.TargetIP, Value: address.String()}, nil
	}
	if looksLikeIPv4(value) {
		return model.Target{}, fmt.Errorf("%w: invalid IPv4 address %q", ErrInvalidTarget, value)
	}

	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if !validDNSName(name) {
		return model.Target{}, fmt.Errorf("%w: %q", ErrInvalidTarget, value)
	}

	return model.Target{Kind: model.TargetDNSName, Value: name}, nil
}

// NewPolicy validates scope entries and returns their normalized form.
func NewPolicy(allowed, excluded []string) (model.ScopePolicy, error) {
	policy := model.ScopePolicy{
		Allowed:  make([]model.Target, 0, len(allowed)),
		Excluded: make([]model.Target, 0, len(excluded)),
	}

	var err error
	policy.Allowed, err = parseUnique(false, allowed)
	if err != nil {
		return model.ScopePolicy{}, err
	}
	policy.Excluded, err = parseUnique(true, excluded)
	if err != nil {
		return model.ScopePolicy{}, err
	}

	return policy, nil
}

// Allows reports whether a normalized target is explicitly allowed and not excluded.
func Allows(policy model.ScopePolicy, target model.Target) bool {
	if contains(policy.Excluded, target) {
		return false
	}
	return contains(policy.Allowed, target)
}

func parseUnique(exclusion bool, values []string) ([]model.Target, error) {
	targets := make([]model.Target, 0, len(values))
	seen := make(map[model.Target]struct{}, len(values))
	for index, value := range values {
		target, err := ParseTarget(value)
		if err != nil {
			return nil, &InputError{exclusion: exclusion, index: index + 1, err: err}
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

// EffectiveTargets returns explicitly allowed targets after applying exclusions.
func EffectiveTargets(policy model.ScopePolicy) []model.Target {
	targets := make([]model.Target, 0, len(policy.Allowed))
	for _, target := range policy.Allowed {
		if !contains(policy.Excluded, target) {
			targets = append(targets, target)
		}
	}
	return targets
}

func contains(targets []model.Target, target model.Target) bool {
	for _, candidate := range targets {
		if candidate == target {
			return true
		}
	}
	return false
}

func looksLikeIPv4(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
