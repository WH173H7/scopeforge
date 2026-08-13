package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/scope"
)

type resolverResponse struct {
	addresses []net.IP
	err       error
}

type fakeResolver struct {
	mu          sync.Mutex
	responses   map[string]resolverResponse
	mxRecords   []*net.MX
	nsRecords   []*net.NS
	cname       string
	mxErr       error
	nsErr       error
	cnameErr    error
	txtRecords  []string
	txtErr      error
	calls       []string
	lookup      func(context.Context, string, string) ([]net.IP, error)
	lookupMX    func(context.Context, string) ([]*net.MX, error)
	lookupNS    func(context.Context, string) ([]*net.NS, error)
	lookupCNAME func(context.Context, string) (string, error)
	lookupTXT   func(context.Context, string) ([]string, error)
}

func (resolver *fakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	resolver.recordCall("txt:" + host)
	if resolver.lookupTXT != nil {
		return resolver.lookupTXT(ctx, host)
	}
	return resolver.txtRecords, resolver.txtErr
}

func (resolver *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	resolver.mu.Lock()
	resolver.calls = append(resolver.calls, network+":"+host)
	resolver.mu.Unlock()
	if resolver.lookup != nil {
		return resolver.lookup(ctx, network, host)
	}
	response := resolver.responses[network]
	return response.addresses, response.err
}

func (resolver *fakeResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	resolver.recordCall("mx:" + host)
	if resolver.lookupMX != nil {
		return resolver.lookupMX(ctx, host)
	}
	return resolver.mxRecords, resolver.mxErr
}

func (resolver *fakeResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	resolver.recordCall("ns:" + host)
	if resolver.lookupNS != nil {
		return resolver.lookupNS(ctx, host)
	}
	return resolver.nsRecords, resolver.nsErr
}

func (resolver *fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	resolver.recordCall("cname:" + host)
	if resolver.lookupCNAME != nil {
		return resolver.lookupCNAME(ctx, host)
	}
	return resolver.cname, resolver.cnameErr
}

func (resolver *fakeResolver) recordCall(call string) {
	resolver.mu.Lock()
	resolver.calls = append(resolver.calls, call)
	resolver.mu.Unlock()
}

func TestCollectAuthorizedDNSEvidence(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{responses: map[string]resolverResponse{
		"ip4": {addresses: []net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20")}},
		"ip6": {addresses: []net.IP{net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}},
	}, mxRecords: []*net.MX{
		{Host: "MAIL2.Example.NET.", Pref: 20},
		{Host: "mail1.example.net.", Pref: 10},
		{Host: "MAIL1.EXAMPLE.NET.", Pref: 10},
	}, nsRecords: []*net.NS{
		{Host: "NS2.Example.NET."}, {Host: "ns1.example.net."}, {Host: "NS1.EXAMPLE.NET."},
	}, cname: "Edge.Provider.NET.", txtRecords: []string{"Verification=Ab C", "v=spf1  include:Example.NET  ~all", "Verification=Ab C"}}

	evidence, failures, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("failures = %#v, want none", failures)
	}
	want := []model.Evidence{
		{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.10"},
		{Target: target, Category: "dns_record", RecordType: "A", Value: "192.0.2.20"},
		{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::1"},
		{Target: target, Category: "dns_record", RecordType: "AAAA", Value: "2001:db8::2"},
		{Target: target, Category: "dns_record", RecordType: "MX", Value: "mail1.example.net", Priority: uint16Pointer(10)},
		{Target: target, Category: "dns_record", RecordType: "MX", Value: "mail2.example.net", Priority: uint16Pointer(20)},
		{Target: target, Category: "dns_record", RecordType: "NS", Value: "ns1.example.net"},
		{Target: target, Category: "dns_record", RecordType: "NS", Value: "ns2.example.net"},
		{Target: target, Category: "dns_record", RecordType: "CNAME", Value: "edge.provider.net"},
		{Target: target, Category: "dns_record", RecordType: "TXT", Value: "Verification=Ab C"},
		{Target: target, Category: "dns_record", RecordType: "TXT", Value: "v=spf1  include:Example.NET  ~all"},
	}
	if len(evidence) != len(want) {
		t.Fatalf("evidence = %#v, want %#v", evidence, want)
	}
	for index := range want {
		if !equalEvidence(evidence[index], want[index]) {
			t.Fatalf("evidence[%d] = %#v, want %#v", index, evidence[index], want[index])
		}
	}
	if len(policy.Allowed) != 1 || policy.Allowed[0] != target {
		t.Fatalf("DNS evidence expanded scope: %#v", policy.Allowed)
	}
}

func TestCollectRejectsUnauthorizedTargetBeforeLookup(t *testing.T) {
	policy, _ := policyAndTarget(t, "example.com")
	unauthorized, _ := scope.ParseTarget("api.example.com")
	resolver := &fakeResolver{}

	_, _, err := Collect(context.Background(), resolver, policy, unauthorized, time.Second)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Collect() error = %v, want ErrUnauthorized", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %v, want none", resolver.calls)
	}
}

func TestCollectRejectsAuthorizedIPBeforeLookup(t *testing.T) {
	policy, target := policyAndTarget(t, "192.0.2.10")
	resolver := &fakeResolver{}

	_, _, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Collect() error = %v, want ErrUnauthorized", err)
	}
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %v, want none", resolver.calls)
	}
}

func TestCollectRepresentsLookupFailureAndNoResult(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{responses: map[string]resolverResponse{
		"ip4": {err: errors.New("resolver unavailable")},
		"ip6": {},
	}}

	evidence, failures, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 0 || len(failures) != 6 {
		t.Fatalf("evidence = %#v, failures = %#v", evidence, failures)
	}
	if failures[0].Code != "lookup_failed" || failures[1].Code != "no_result" {
		t.Fatalf("failure codes = %q, %q", failures[0].Code, failures[1].Code)
	}
}

func TestCollectCancellation(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := &fakeResolver{lookup: func(ctx context.Context, _, _ string) ([]net.IP, error) {
		return nil, ctx.Err()
	}}

	_, failures, err := Collect(ctx, resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].Code != "canceled" {
		t.Fatalf("failures = %#v, want one cancellation", failures)
	}
	if len(resolver.calls) != 1 {
		t.Fatalf("resolver calls = %v, want collection to stop after cancellation", resolver.calls)
	}
}

func TestCollectTimeout(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{lookup: func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	resolver.lookupMX = func(ctx context.Context, _ string) ([]*net.MX, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	resolver.lookupNS = func(ctx context.Context, _ string) ([]*net.NS, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	resolver.lookupCNAME = func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	resolver.lookupTXT = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	_, failures, err := Collect(context.Background(), resolver, policy, target, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 6 {
		t.Fatalf("failures = %#v, want six timeouts", failures)
	}
	for _, failure := range failures {
		if failure.Code != "timeout" {
			t.Fatalf("failure = %#v, want timeout", failure)
		}
	}
}

func TestCollectBoundedTXTEvidence(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	values := make([]string, 0, 68)
	values = append(values, "", "Case  PRESERVED", "Case  PRESERVED", strings.Repeat("A", maxTXTValueBytes+10))
	for index := 0; index < 64; index++ {
		values = append(values, fmt.Sprintf("record-%02d", index))
	}
	resolver := &fakeResolver{responses: map[string]resolverResponse{}, txtRecords: values}
	evidence, outcomes, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	txt := evidenceByType(evidence, "TXT")
	if len(txt) != maxTXTRecords {
		t.Fatalf("retained TXT records = %d, want %d", len(txt), maxTXTRecords)
	}
	seenEmpty, seenCase := false, false
	for _, item := range txt {
		seenEmpty = seenEmpty || item.Value == ""
		seenCase = seenCase || item.Value == "Case  PRESERVED"
	}
	if !seenEmpty || !seenCase {
		t.Fatalf("TXT case/whitespace/empty values changed")
	}
	var limited *model.RunError
	for index := range outcomes {
		if outcomes[index].Code == "evidence_limited" {
			limited = &outcomes[index]
		}
	}
	if limited == nil || limited.OmittedRecords == 0 || limited.OmittedBytes == 0 {
		t.Fatalf("limit outcome = %#v, want explicit omissions", limited)
	}
	for _, item := range txt {
		if item.Truncated {
			if item.OriginalLength == nil || *item.OriginalLength != maxTXTValueBytes+10 || len(item.Value) != maxTXTValueBytes {
				t.Fatalf("truncated TXT = %#v", item)
			}
			return
		}
	}
	t.Fatal("missing truncated oversized TXT value")
}

func TestBoundedTXTTotalByteLimit(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	values := make([]string, 20)
	for index := range values {
		values[index] = fmt.Sprintf("%02d-%s", index, strings.Repeat("x", 4093))
	}
	evidence, outcome := boundedTXT(target, values)
	retainedBytes := 0
	for _, item := range evidence {
		if item.Encoding == "" {
			retainedBytes += len(item.Value)
		}
	}
	if retainedBytes > maxTXTBytesPerTarget || outcome == nil || outcome.OmittedRecords == 0 || outcome.OmittedBytes == 0 {
		t.Fatalf("retained=%d outcome=%#v", retainedBytes, outcome)
	}
}

func TestBoundedTXTPerValueTruncationIsTyped(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	value := strings.Repeat("B", maxTXTValueBytes+25)
	evidence, outcome := boundedTXT(target, []string{value})
	if outcome != nil {
		t.Fatalf("per-value truncation emitted evidence_limited: %#v", outcome)
	}
	if len(evidence) != 1 || !evidence[0].Truncated || evidence[0].Encoding != "" {
		t.Fatalf("truncated evidence = %#v", evidence)
	}
	if evidence[0].OriginalLength == nil || *evidence[0].OriginalLength != len(value) || len(evidence[0].Value) != maxTXTValueBytes {
		t.Fatalf("truncated lengths = %#v", evidence[0])
	}
}

func TestBoundedTXTInvalidUTF8UsesBase64(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	value := string([]byte{'a', 0xff, 'b'})
	evidence, outcome := boundedTXT(target, []string{value})
	if outcome != nil || len(evidence) != 1 || evidence[0].Encoding != "base64" || evidence[0].Value != "Yf9i" {
		t.Fatalf("invalid UTF-8 evidence = %#v, outcome = %#v", evidence, outcome)
	}
}

func TestBoundedTXTPreservesValidUTF8(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	value := "café 日本語"
	evidence, outcome := boundedTXT(target, []string{value})
	if outcome != nil || len(evidence) != 1 || evidence[0].Encoding != "" || evidence[0].Value != value {
		t.Fatalf("valid UTF-8 evidence = %#v, outcome = %#v", evidence, outcome)
	}
}

func TestBoundedTXTTruncatedInvalidUTF8KeepsOriginalLength(t *testing.T) {
	target := model.Target{Kind: model.TargetDNSName, Value: "example.com"}
	raw := append(bytes.Repeat([]byte{'x'}, maxTXTValueBytes), 0xff, 'y')
	evidence, outcome := boundedTXT(target, []string{string(raw)})
	if outcome != nil || len(evidence) != 1 {
		t.Fatalf("evidence = %#v outcome = %#v", evidence, outcome)
	}
	item := evidence[0]
	if item.Encoding != "base64" || !item.Truncated || item.OriginalLength == nil || *item.OriginalLength != len(raw) {
		t.Fatalf("truncated invalid UTF-8 = %#v", item)
	}
}

func TestCollectTXTAbsenceIsNoResult(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{
		responses:  map[string]resolverResponse{},
		txtRecords: []string{},
		txtErr:     &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
	}
	evidence, outcomes, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidenceByType(evidence, "TXT")) != 0 {
		t.Fatalf("unexpected TXT evidence: %#v", evidence)
	}
	assertOutcome(t, outcomes, "TXT", "no_result")
}

func TestCollectTXTFailureCancellationAndAuthorization(t *testing.T) {
	t.Run("failure", func(t *testing.T) {
		policy, target := policyAndTarget(t, "example.com")
		resolver := &fakeResolver{responses: map[string]resolverResponse{}, txtErr: errors.New("TXT failure")}
		_, outcomes, err := Collect(context.Background(), resolver, policy, target, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		assertOutcome(t, outcomes, "TXT", "lookup_failed")
	})
	t.Run("authorization", func(t *testing.T) {
		policy, target := policyAndTarget(t, "example.com")
		resolver := &fakeResolver{responses: map[string]resolverResponse{}}
		resolver.lookupCNAME = func(context.Context, string) (string, error) { policy.Allowed[0] = model.Target{}; return "", nil }
		_, _, err := Collect(context.Background(), resolver, policy, target, time.Second)
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v", err)
		}
		for _, call := range resolver.calls {
			if call == "txt:example.com" {
				t.Fatal("unauthorized TXT lookup occurred")
			}
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		policy, target := policyAndTarget(t, "example.com")
		ctx, cancel := context.WithCancel(context.Background())
		resolver := &fakeResolver{responses: map[string]resolverResponse{}}
		resolver.lookupTXT = func(context.Context, string) ([]string, error) { cancel(); return nil, context.Canceled }
		_, outcomes, err := Collect(ctx, resolver, policy, target, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		assertOutcome(t, outcomes, "TXT", "canceled")
	})
}

func evidenceByType(evidence []model.Evidence, recordType string) []model.Evidence {
	result := make([]model.Evidence, 0)
	for _, item := range evidence {
		if item.RecordType == recordType {
			result = append(result, item)
		}
	}
	return result
}

func assertOutcome(t *testing.T, outcomes []model.RunError, recordType, code string) {
	t.Helper()
	for _, outcome := range outcomes {
		if outcome.RecordType == recordType && outcome.Code == code {
			return
		}
	}
	t.Fatalf("missing %s/%s outcome in %#v", recordType, code, outcomes)
}

func TestCollectDoesNotManufactureCNAMEEvidence(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{responses: map[string]resolverResponse{}, cname: "EXAMPLE.COM."}
	evidence, failures, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range evidence {
		if item.RecordType == "CNAME" {
			t.Fatalf("false CNAME evidence = %#v", item)
		}
	}
	assertOutcome(t, failures, "CNAME", "no_result")
}

func TestCollectRepresentsNewLookupFailures(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{
		responses: map[string]resolverResponse{}, mxErr: errors.New("MX failure"),
		nsErr: errors.New("NS failure"), cnameErr: errors.New("CNAME failure"),
	}
	_, failures, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"MX": "lookup_failed", "NS": "lookup_failed", "CNAME": "lookup_failed"}
	for _, failure := range failures {
		if code, ok := want[failure.RecordType]; ok {
			if failure.Code != code {
				t.Fatalf("%s failure = %#v", failure.RecordType, failure)
			}
			delete(want, failure.RecordType)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing failure types: %v", want)
	}
}

func TestCollectTreatsResolverNotFoundAsNoResult(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{
		responses: map[string]resolverResponse{},
		mxErr:     &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
	}
	_, failures, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range failures {
		if failure.RecordType == "MX" {
			if failure.Code != "no_result" || failure.Retryable {
				t.Fatalf("MX outcome = %#v, want non-retryable no_result", failure)
			}
			return
		}
	}
	t.Fatal("missing MX outcome")
}

func TestCollectPreservesNullMX(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{
		responses: map[string]resolverResponse{},
		mxRecords: []*net.MX{{Host: ".", Pref: 0}},
	}
	evidence, outcomes, err := Collect(context.Background(), resolver, policy, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var nullMX *model.Evidence
	for index := range evidence {
		if evidence[index].RecordType == "MX" {
			nullMX = &evidence[index]
		}
	}
	if nullMX == nil || nullMX.Value != "." || nullMX.Priority == nil || *nullMX.Priority != 0 {
		t.Fatalf("Null MX evidence = %#v, want value . and priority 0", nullMX)
	}
	for _, outcome := range outcomes {
		if outcome.RecordType == "MX" && outcome.Code == "no_result" {
			t.Fatalf("Null MX was converted to no_result: %#v", outcome)
		}
	}
	if len(policy.Allowed) != 1 || policy.Allowed[0] != target {
		t.Fatalf("Null MX expanded scope: %#v", policy.Allowed)
	}
}

func TestCollectChecksAuthorizationBeforeNewLookups(t *testing.T) {
	tests := []struct {
		name      string
		revokeAt  string
		forbidden string
	}{
		{name: "MX", revokeAt: "ip6", forbidden: "mx:example.com"},
		{name: "NS", revokeAt: "mx", forbidden: "ns:example.com"},
		{name: "CNAME", revokeAt: "ns", forbidden: "cname:example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, target := policyAndTarget(t, "example.com")
			resolver := &fakeResolver{responses: map[string]resolverResponse{}}
			revoke := func() { policy.Allowed[0] = model.Target{} }
			switch test.revokeAt {
			case "ip6":
				resolver.lookup = func(_ context.Context, network, _ string) ([]net.IP, error) {
					if network == "ip6" {
						revoke()
					}
					return nil, nil
				}
			case "mx":
				resolver.lookupMX = func(context.Context, string) ([]*net.MX, error) { revoke(); return nil, nil }
			case "ns":
				resolver.lookupNS = func(context.Context, string) ([]*net.NS, error) { revoke(); return nil, nil }
			}
			_, _, err := Collect(context.Background(), resolver, policy, target, time.Second)
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Collect() error = %v, want ErrUnauthorized", err)
			}
			for _, call := range resolver.calls {
				if call == test.forbidden {
					t.Fatalf("unauthorized lookup occurred: %v", resolver.calls)
				}
			}
		})
	}
}

func equalEvidence(left, right model.Evidence) bool {
	if left.Target != right.Target || left.Category != right.Category || left.RecordType != right.RecordType || left.Value != right.Value {
		return false
	}
	if left.Priority == nil || right.Priority == nil {
		return left.Priority == nil && right.Priority == nil
	}
	return *left.Priority == *right.Priority
}

func uint16Pointer(value uint16) *uint16 {
	return &value
}

func policyAndTarget(t *testing.T, value string) (model.ScopePolicy, model.Target) {
	t.Helper()
	policy, err := scope.NewPolicy([]string{value}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return policy, policy.Allowed[0]
}
