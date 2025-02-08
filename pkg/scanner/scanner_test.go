package scanner

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	opts := Options{
		Patterns:       []string{"<script>alert(1)</script>"},
		Verbose:        true,
		MLModel:        "../../models/default.json",
		MLThreshold:    0.7,
		ExcludeUrls:    []string{},
		IncludeParams:  []string{},
		TimeoutSeconds: 30,
		MaxConcurrency: 5,
		Headers:        map[string]string{},
	}

	s, err := NewScanner(opts)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	if s == nil {
		t.Fatal("Scanner should not be nil")
	}

	if len(s.patterns) == 0 {
		t.Error("Scanner should have at least one pattern")
	}

	if s.config.TimeoutSeconds != 30 {
		t.Errorf("Expected timeout 30, got %d", s.config.TimeoutSeconds)
	}

	if s.config.MaxConcurrency != 5 {
		t.Errorf("Expected max concurrency 5, got %d", s.config.MaxConcurrency)
	}
}
