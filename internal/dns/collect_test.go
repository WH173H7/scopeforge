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
	mu        sync.Mutex
	responses map[string]resolverResponse
	calls     []string
	lookup    func(context.Context, string, string) ([]net.IP, error)
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

func TestCollectAuthorizedDNSEvidence(t *testing.T) {
	policy, target := policyAndTarget(t, "example.com")
	resolver := &fakeResolver{responses: map[string]resolverResponse{
		"ip4": {addresses: []net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20")}},
		"ip6": {addresses: []net.IP{net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}},
	}}

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
	}
	if len(evidence) != len(want) {
		t.Fatalf("evidence = %#v, want %#v", evidence, want)
	}
	for index := range want {
		if evidence[index] != want[index] {
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
	if len(evidence) != 0 || len(failures) != 2 {
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

	_, failures, err := Collect(context.Background(), resolver, policy, target, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 2 || failures[0].Code != "timeout" || failures[1].Code != "timeout" {
		t.Fatalf("failures = %#v, want two timeouts", failures)
	}
}

func policyAndTarget(t *testing.T, value string) (model.ScopePolicy, model.Target) {
	t.Helper()
	policy, err := scope.NewPolicy([]string{value}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return policy, policy.Allowed[0]
}
