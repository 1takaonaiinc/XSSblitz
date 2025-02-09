package payloadgen

import (
	"strings"
	"testing"
)

func TestGeneratePayloads(t *testing.T) {
	tests := []struct {
		name    string
		context string
		count   int
		want    []string
	}{
		{
			name:    "Basic payload generation",
			context: "",
			count:   1,
			want:    []string{"<script>alert(1)</script>"},
		},
		{
			name:    "Textarea context",
			context: "textarea",
			count:   1,
			want:    []string{"<script>alert(1)</script>"},
		},
		{
			name:    "Javascript context",
			context: "javascript:",
			count:   1,
			want:    []string{"<script>alert(1)</script>"},
		},
		{
			name:    "Multiple variants",
			context: "",
			count:   3,
			want: []string{
				"<script>alert(1)</script>",
				"<script>prompt(1)</script>",
				"<script>confirm(1)</script>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator()
			got := gen.Generate(tt.context, tt.count)

			if len(got) != len(tt.want) {
				t.Errorf("Generate() returned %d payloads, want %d", len(got), len(tt.want))
			}

			// Check if expected payloads are present
			for _, wantPayload := range tt.want {
				found := false
				for _, gotPayload := range got {
					if gotPayload == wantPayload {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Generate() missing expected payload: %s", wantPayload)
				}
			}
		})
	}
}

func TestMutations(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		mutation   string
		shouldHave string
	}{
		{
			name:       "Case mutation",
			payload:    "<script>alert(1)</script>",
			mutation:   "case",
			shouldHave: "SCRIPT",
		},
		{
			name:       "Encoding mutation",
			payload:    "<script>alert(1)</script>",
			mutation:   "encoding",
			shouldHave: "&lt;",
		},
		{
			name:       "Prefix mutation",
			payload:    "<script>alert(1)</script>",
			mutation:   "prefix",
			shouldHave: "-->",
		},
		{
			name:       "Suffix mutation",
			payload:    "<script>alert(1)</script>",
			mutation:   "suffix",
			shouldHave: "<!--",
		},
	}

	gen := NewGenerator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variants := gen.createVariants(tt.payload, 10)
			found := false
			for _, variant := range variants {
				if strings.Contains(variant, tt.shouldHave) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("createVariants() did not apply %s mutation, should contain %s", tt.mutation, tt.shouldHave)
			}
		})
	}
}

func TestContextAwareMutations(t *testing.T) {
	tests := []struct {
		name    string
		context string
		check   func(payload string) bool
	}{
		{
			name:    "Textarea escaping",
			context: "textarea",
			check: func(payload string) bool {
				return !strings.Contains(payload, "\"")
			},
		},
		{
			name:    "JavaScript escaping",
			context: "javascript:",
			check: func(payload string) bool {
				return strings.Contains(payload, "\\'") || strings.Contains(payload, "\\\"")
			},
		},
		{
			name:    "Attribute escaping",
			context: "=",
			check: func(payload string) bool {
				return strings.Contains(payload, "&quot;") || strings.Contains(payload, "&#39;")
			},
		},
	}

	gen := NewGenerator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := gen.Generate(tt.context, 5)
			if len(payloads) == 0 {
				t.Error("Generate() returned no payloads")
				return
			}

			for _, payload := range payloads {
				if !tt.check(payload) {
					t.Errorf("Generate() with context %s produced invalid payload: %s", tt.context, payload)
				}
			}
		})
	}
}
