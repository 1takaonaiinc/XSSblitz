package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// MLModel represents the structure of our ML model data
type MLModel struct {
	Weights   map[string]float64 `json:"weights"`
	Threshold float64            `json:"threshold"`
	Version   string             `json:"version"`
}

// DefaultMLPredictor implements the MLPredictor interface
type DefaultMLPredictor struct {
	model    *MLModel
	features []string
}

func NewMLPredictor(modelPath string) (MLPredictor, error) {
	// Load and parse the model file
	modelData, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %w", err)
	}

	var model MLModel
	if err := json.Unmarshal(modelData, &model); err != nil {
		return nil, fmt.Errorf("failed to parse model data: %w", err)
	}

	// Extract features from model weights
	features := make([]string, 0, len(model.Weights))
	for feature := range model.Weights {
		features = append(features, feature)
	}

	return &DefaultMLPredictor{
		model:    &model,
		features: features,
	}, nil
}

func (p *DefaultMLPredictor) Predict(content string) (bool, float64, []string) {
	score := 0.0
	var contributions []string

	// Calculate prediction score based on feature presence
	for feature, weight := range p.model.Weights {
		if containsFeature(content, feature) {
			score += weight
			contributions = append(contributions, feature)
		}
	}

	// Normalize score to 0-1 range
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}

	isVulnerable := score >= p.model.Threshold

	return isVulnerable, score, contributions
}

// containsFeature checks if the content contains a specific feature pattern
func containsFeature(content, feature string) bool {
	// Convert both strings to lowercase for case-insensitive comparison
	contentLower := strings.ToLower(content)
	featureLower := strings.ToLower(feature)

	// Look for common XSS patterns
	patterns := []string{
		fmt.Sprintf("<%s", featureLower),           // Tag opening
		fmt.Sprintf("%s=", featureLower),           // Attribute assignment
		fmt.Sprintf("\"%s\"", featureLower),        // Quoted string
		fmt.Sprintf("'%s'", featureLower),          // Single-quoted string
		fmt.Sprintf("javascript:%s", featureLower), // JavaScript protocol
		fmt.Sprintf("data:%s", featureLower),       // Data URI scheme
	}

	for _, pattern := range patterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return strings.Contains(contentLower, featureLower)
}

// Helper functions for feature extraction
func extractJavaScriptEvents(content string) []string {
	events := []string{
		"onabort", "onblur", "onchange", "onclick", "ondblclick",
		"onerror", "onfocus", "onkeydown", "onkeypress", "onkeyup",
		"onload", "onmousedown", "onmousemove", "onmouseout",
		"onmouseover", "onmouseup", "onreset", "onresize",
		"onselect", "onsubmit", "onunload",
	}

	var found []string
	contentLower := strings.ToLower(content)

	for _, event := range events {
		if strings.Contains(contentLower, event) {
			found = append(found, event)
		}
	}

	return found
}

func extractHTMLTags(content string) []string {
	tags := []string{
		"script", "img", "iframe", "object", "embed",
		"form", "input", "button", "a", "svg",
	}

	var found []string
	contentLower := strings.ToLower(content)

	for _, tag := range tags {
		if strings.Contains(contentLower, "<"+tag) {
			found = append(found, tag)
		}
	}

	return found
}

func extractURLParameters(content string) []string {
	var params []string
	parts := strings.Split(content, "?")
	if len(parts) > 1 {
		queryParts := strings.Split(parts[1], "&")
		for _, param := range queryParts {
			if strings.Contains(param, "=") {
				paramName := strings.Split(param, "=")[0]
				params = append(params, paramName)
			}
		}
	}
	return params
}
