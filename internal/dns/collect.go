package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/scope"
)

var ErrUnauthorized = errors.New("DNS target is not authorized")

// Resolver is the narrow part of net.Resolver used for A and AAAA lookups.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// Collect obtains A and AAAA evidence for one explicitly authorized DNS target.
func Collect(
	ctx context.Context,
	resolver Resolver,
	policy model.ScopePolicy,
	target model.Target,
	timeout time.Duration,
) ([]model.Evidence, []model.RunError, error) {
	if target.Kind != model.TargetDNSName {
		return nil, nil, ErrUnauthorized
	}

	evidence := make([]model.Evidence, 0)
	failures := make([]model.RunError, 0)
	for _, query := range []struct {
		network    string
		recordType string
	}{
		{network: "ip4", recordType: "A"},
		{network: "ip6", recordType: "AAAA"},
	} {
		if !scope.Allows(policy, target) {
			return evidence, failures, ErrUnauthorized
		}
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		addresses, err := resolver.LookupIP(lookupCtx, query.network, target.Value)
		lookupContextError := lookupCtx.Err()
		cancel()
		if err != nil {
			failures = append(failures, lookupFailure(target, query.recordType, err, lookupContextError))
			if ctx.Err() != nil {
				return evidence, failures, nil
			}
			continue
		}

		values := normalizedAddresses(addresses, query.recordType)
		if len(values) == 0 {
			failures = append(failures, model.RunError{
				Code:       "no_result",
				Message:    "DNS lookup returned no records",
				Collector:  "dns",
				Target:     targetPointer(target),
				RecordType: query.recordType,
			})
			continue
		}
		for _, value := range values {
			evidence = append(evidence, model.Evidence{
				Target: target, Category: "dns_record", RecordType: query.recordType, Value: value,
			})
		}
	}

	return evidence, failures, nil
}

func normalizedAddresses(addresses []net.IP, recordType string) []string {
	unique := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address)
		if !ok {
			continue
		}
		parsed = parsed.Unmap()
		if (recordType == "A" && !parsed.Is4()) || (recordType == "AAAA" && !parsed.Is6()) {
			continue
		}
		unique[parsed.String()] = struct{}{}
	}

	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func lookupFailure(target model.Target, recordType string, err, contextError error) model.RunError {
	code := "lookup_failed"
	message := "DNS lookup failed"
	retryable := true
	if errors.Is(contextError, context.Canceled) || errors.Is(err, context.Canceled) {
		code = "canceled"
		message = "DNS lookup canceled"
		retryable = false
	} else if errors.Is(contextError, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
		message = "DNS lookup timed out"
	}
	return model.RunError{
		Code: code, Message: message, Collector: "dns", Target: targetPointer(target),
		RecordType: recordType, Retryable: retryable,
	}
}

func targetPointer(target model.Target) *model.Target {
	copy := target
	return &copy
}
