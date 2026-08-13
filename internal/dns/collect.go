package dns

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/scope"
)

var ErrUnauthorized = errors.New("DNS target is not authorized")

const (
	maxTXTRecords        = 64
	maxTXTValueBytes     = 4096
	maxTXTBytesPerTarget = 65536
)

// Resolver is the narrow part of net.Resolver used for supported DNS lookups.
type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupTXT(context.Context, string) ([]string, error)
}

// Collect obtains supported DNS evidence for one explicitly authorized DNS target.
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

	if !scope.Allows(policy, target) {
		return evidence, failures, ErrUnauthorized
	}
	mxCtx, cancel := context.WithTimeout(ctx, timeout)
	mxRecords, err := resolver.LookupMX(mxCtx, target.Value)
	mxContextError := mxCtx.Err()
	cancel()
	if err != nil {
		failures = append(failures, lookupFailure(target, "MX", err, mxContextError))
		if ctx.Err() != nil {
			return evidence, failures, nil
		}
	} else {
		mxEvidence := normalizedMX(target, mxRecords)
		if len(mxEvidence) == 0 {
			failures = append(failures, noResult(target, "MX"))
		} else {
			evidence = append(evidence, mxEvidence...)
		}
	}

	if !scope.Allows(policy, target) {
		return evidence, failures, ErrUnauthorized
	}
	nsCtx, cancel := context.WithTimeout(ctx, timeout)
	nsRecords, err := resolver.LookupNS(nsCtx, target.Value)
	nsContextError := nsCtx.Err()
	cancel()
	if err != nil {
		failures = append(failures, lookupFailure(target, "NS", err, nsContextError))
		if ctx.Err() != nil {
			return evidence, failures, nil
		}
	} else {
		nsEvidence := normalizedNS(target, nsRecords)
		if len(nsEvidence) == 0 {
			failures = append(failures, noResult(target, "NS"))
		} else {
			evidence = append(evidence, nsEvidence...)
		}
	}

	if !scope.Allows(policy, target) {
		return evidence, failures, ErrUnauthorized
	}
	cnameCtx, cancel := context.WithTimeout(ctx, timeout)
	canonicalName, err := resolver.LookupCNAME(cnameCtx, target.Value)
	cnameContextError := cnameCtx.Err()
	cancel()
	if err != nil {
		failures = append(failures, lookupFailure(target, "CNAME", err, cnameContextError))
		if ctx.Err() != nil {
			return evidence, failures, nil
		}
	} else {
		canonicalName = normalizedDNSName(canonicalName)
		if canonicalName == "" || canonicalName == target.Value {
			failures = append(failures, noResult(target, "CNAME"))
		} else {
			evidence = append(evidence, model.Evidence{
				Target: target, Category: "dns_record", RecordType: "CNAME", Value: canonicalName,
			})
		}
	}

	if !scope.Allows(policy, target) {
		return evidence, failures, ErrUnauthorized
	}
	txtCtx, cancel := context.WithTimeout(ctx, timeout)
	txtRecords, err := resolver.LookupTXT(txtCtx, target.Value)
	txtContextError := txtCtx.Err()
	cancel()
	if err != nil {
		failures = append(failures, lookupFailure(target, "TXT", err, txtContextError))
	} else {
		txtEvidence, limitOutcome := boundedTXT(target, txtRecords)
		if len(txtEvidence) == 0 && limitOutcome == nil {
			failures = append(failures, noResult(target, "TXT"))
		} else {
			evidence = append(evidence, txtEvidence...)
			if limitOutcome != nil {
				failures = append(failures, *limitOutcome)
			}
		}
	}

	return evidence, failures, nil
}

func boundedTXT(target model.Target, records []string) ([]model.Evidence, *model.RunError) {
	unique := make(map[string]struct{}, len(records))
	for _, value := range records {
		unique[value] = struct{}{}
	}
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Strings(values)

	evidence := make([]model.Evidence, 0, min(len(values), maxTXTRecords))
	retainedBytes := 0
	omittedRecords, omittedBytes := 0, 0
	for _, value := range values {
		originalLength := len(value)
		if len(evidence) == maxTXTRecords || retainedBytes == maxTXTBytesPerTarget {
			omittedRecords++
			omittedBytes += originalLength
			continue
		}

		retainLength := min(originalLength, maxTXTValueBytes, maxTXTBytesPerTarget-retainedBytes)
		retained := []byte(value)[:retainLength]
		item := model.Evidence{Target: target, Category: "dns_record", RecordType: "TXT"}
		if utf8.ValidString(value) {
			for retainLength > 0 && !utf8.Valid(retained) {
				retainLength--
				retained = retained[:retainLength]
			}
			item.Value = string(retained)
		} else {
			item.Value = base64.StdEncoding.EncodeToString(retained)
			item.Encoding = "base64"
		}
		retainedBytes += len(retained)
		if len(retained) < originalLength {
			item.Truncated = true
			item.OriginalLength = intPointer(originalLength)
			omittedBytes += originalLength - len(retained)
		}
		evidence = append(evidence, item)
	}

	if omittedRecords == 0 && omittedBytes == 0 {
		return evidence, nil
	}
	return evidence, &model.RunError{
		Code: "evidence_limited", Message: "TXT evidence exceeded retention limits", Collector: "dns",
		Target: targetPointer(target), RecordType: "TXT", OmittedRecords: omittedRecords, OmittedBytes: omittedBytes,
	}
}

func intPointer(value int) *int {
	return &value
}

func normalizedMX(target model.Target, records []*net.MX) []model.Evidence {
	type mxKey struct {
		preference uint16
		host       string
	}
	unique := make(map[mxKey]struct{}, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		host := normalizedMXHost(record.Host)
		if host != "" {
			unique[mxKey{preference: record.Pref, host: host}] = struct{}{}
		}
	}
	keys := make([]mxKey, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].preference != keys[j].preference {
			return keys[i].preference < keys[j].preference
		}
		return keys[i].host < keys[j].host
	})
	evidence := make([]model.Evidence, 0, len(keys))
	for _, key := range keys {
		preference := key.preference
		evidence = append(evidence, model.Evidence{
			Target: target, Category: "dns_record", RecordType: "MX", Value: key.host, Priority: &preference,
		})
	}
	return evidence
}

func normalizedMXHost(host string) string {
	if host == "." {
		return "."
	}
	return normalizedDNSName(host)
}

func normalizedNS(target model.Target, records []*net.NS) []model.Evidence {
	unique := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		host := normalizedDNSName(record.Host)
		if host != "" {
			unique[host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(unique))
	for host := range unique {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	evidence := make([]model.Evidence, 0, len(hosts))
	for _, host := range hosts {
		evidence = append(evidence, model.Evidence{
			Target: target, Category: "dns_record", RecordType: "NS", Value: host,
		})
	}
	return evidence
}

func normalizedDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func noResult(target model.Target, recordType string) model.RunError {
	return model.RunError{
		Code: "no_result", Message: "DNS lookup returned no records", Collector: "dns",
		Target: targetPointer(target), RecordType: recordType,
	}
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
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		return noResult(target, recordType)
	} else if errors.Is(contextError, context.Canceled) || errors.Is(err, context.Canceled) {
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
