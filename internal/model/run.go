package model

import (
	"encoding/json"
	"time"
)

// RunStatus describes the lifecycle result of a reconnaissance run.
type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
	RunFailed    RunStatus = "failed"
	RunCanceled  RunStatus = "canceled"
)

// Run captures the inputs and results of one reconnaissance execution.
type Run struct {
	ID           string        `json:"id"`
	StartedAt    time.Time     `json:"started_at"`
	FinishedAt   *time.Time    `json:"finished_at,omitempty"`
	Status       RunStatus     `json:"status"`
	Scope        ScopePolicy   `json:"scope"`
	Observations []Observation `json:"observations"`
	Errors       []RunError    `json:"errors,omitempty"`
}

// Observation is a normalized fact reported by a collector.
type Observation struct {
	Kind       string                     `json:"kind"`
	Collector  string                     `json:"collector"`
	Subject    Target                     `json:"subject"`
	ObservedAt time.Time                  `json:"observed_at"`
	Fields     map[string]json.RawMessage `json:"fields,omitempty"`
	Evidence   []Evidence                 `json:"evidence,omitempty"`
}

// Evidence preserves source material separately from derived observations.
type Evidence struct {
	Source     string    `json:"source"`
	CapturedAt time.Time `json:"captured_at"`
	MediaType  string    `json:"media_type"`
	Content    []byte    `json:"content,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
}

// RunError records an operational failure that did not prevent run creation.
type RunError struct {
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Collector  string    `json:"collector,omitempty"`
	Target     *Target   `json:"target,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
	Retryable  bool      `json:"retryable"`
}
