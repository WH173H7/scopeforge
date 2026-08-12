package model

// TargetKind identifies how a target value is interpreted.
type TargetKind string

const (
	TargetDNSName TargetKind = "dns_name"
	TargetIP      TargetKind = "ip"
)

// Target is a normalized asset named in a scope policy or observation.
type Target struct {
	Kind  TargetKind `json:"kind"`
	Value string     `json:"value"`
}

// ScopePolicy is the authorization policy snapshotted for a run.
type ScopePolicy struct {
	Allowed  []Target `json:"allowed"`
	Excluded []Target `json:"excluded,omitempty"`
}
