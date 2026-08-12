package dns

import (
	"context"
	"errors"
	"net"
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
	calls       []string
	lookup      func(context.Context, string, string) ([]net.IP, error)
	lookupMX    func(context.Context, string) ([]*net.MX, error)
	lookupNS    func(context.Context, string) ([]*net.NS, error)
	lookupCNAME func(context.Context, string) (string, error)
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
	}, cname: "Edge.Provider.NET."}

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
	if len(evidence) != 0 || len(failures) != 5 {
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

	_, failures, err := Collect(context.Background(), resolver, policy, target, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 5 {
		t.Fatalf("failures = %#v, want five timeouts", failures)
	}
	for _, failure := range failures {
		if failure.Code != "timeout" {
			t.Fatalf("failure = %#v, want timeout", failure)
		}
	}
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
	if failures[len(failures)-1].Code != "no_result" || failures[len(failures)-1].RecordType != "CNAME" {
		t.Fatalf("CNAME outcome = %#v", failures[len(failures)-1])
	}
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
