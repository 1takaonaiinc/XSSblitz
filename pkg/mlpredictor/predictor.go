package mlpredictor

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Predictor represents an ML-based XSS detection predictor
type Predictor struct {
	modelPath string
	model     map[string]float64
	threshold float64
	features  []string
}

type Contribution struct {
	Feature string
	Weight  float64
}

// NewPredictor creates a new Predictor with the given model file
func NewPredictor(modelPath string) (*Predictor, error) {
	if modelPath == "" {
		return nil, fmt.Errorf("model path cannot be empty")
	}

	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %w", err)
	}

	var model map[string]float64
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("failed to parse model file: %w", err)
	}

	features := make([]string, 0, len(model))
	for feature := range model {
		features = append(features, feature)
	}

	return &Predictor{
		modelPath: modelPath,
		model:     model,
		threshold: 0.7, // Default threshold
		features:  features,
	}, nil
}

// SetThreshold sets the detection threshold
func (p *Predictor) SetThreshold(threshold float64) {
	p.threshold = threshold
}

// IsXSS predicts if the given content contains XSS
func (p *Predictor) IsXSS(content string) (bool, float64, []Contribution) {
	// Calculate feature presence
	score := 0.0
	var contributions []Contribution

	contentLower := strings.ToLower(content)
	for feature, weight := range p.model {
		if strings.Contains(contentLower, strings.ToLower(feature)) {
			score += weight
			contributions = append(contributions, Contribution{
				Feature: feature,
				Weight:  weight,
			})
		}
	}

	// Normalize score using sigmoid function
	normalizedScore := 1 / (1 + exp(-score))

	return normalizedScore >= p.threshold, normalizedScore, contributions
}

// Helper function to calculate e^x
func exp(x float64) float64 {
	if x > 88.0 {
		return 1.0
	}
	if x < -88.0 {
		return 0.0
	}

	y := 1.0
	n := int(x)
	x -= float64(n)

	if n > 0 {
		for i := 0; i < n; i++ {
			y *= 2.718281828459045
		}
	} else {
		for i := 0; i > n; i-- {
			y /= 2.718281828459045
		}
	}

	return y * (1.0 + x*(1.0+x*(1.0/2.0+x*(1.0/6.0))))
}

// ExtractFeatures returns a list of detected features in the content
func (p *Predictor) ExtractFeatures(content string) []string {
	var detected []string
	contentLower := strings.ToLower(content)

	for _, feature := range p.features {
		if strings.Contains(contentLower, strings.ToLower(feature)) {
			detected = append(detected, feature)
		}
	}

	return detected
}

// GetThreshold returns the current detection threshold
func (p *Predictor) GetThreshold() float64 {
	return p.threshold
}
