package detector

import (
	"fmt"
	"strings"
)

type DetectionResult struct {
	IsVulnerable  bool
	Confidence    float64
	Evidence      string
	DetectionType string
	Severity      string
}

type Config struct {
	MLModelPath    string
	MLThreshold    float64
	PatternRules   []PatternRule
	EnableML       bool
	EnablePatterns bool
}

type PatternRule struct {
	Pattern     string
	Severity    string
	Description string
}

var defaultPatterns = []PatternRule{
	{Pattern: "<script>", Severity: "High", Description: "Basic script tag injection"},
	{Pattern: "javascript:", Severity: "High", Description: "JavaScript protocol handler"},
	{Pattern: "onerror=", Severity: "High", Description: "Error event handler injection"},
	{Pattern: "onload=", Severity: "High", Description: "Load event handler injection"},
	{Pattern: "onclick=", Severity: "Medium", Description: "Click event handler injection"},
	{Pattern: "onmouseover=", Severity: "Medium", Description: "Mouse event handler injection"},
	{Pattern: "eval(", Severity: "High", Description: "JavaScript eval function"},
	{Pattern: "alert(", Severity: "Medium", Description: "JavaScript alert function"},
	{Pattern: "document.cookie", Severity: "High", Description: "Cookie access attempt"},
	{Pattern: "localStorage", Severity: "Medium", Description: "LocalStorage access attempt"},
}

type Detector struct {
	config   Config
	mlModel  MLPredictor
	patterns []PatternRule
}

type MLPredictor interface {
	Predict(content string) (bool, float64, []string)
}

func NewDetector(cfg Config) (*Detector, error) {
	patterns := defaultPatterns
	if len(cfg.PatternRules) > 0 {
		patterns = cfg.PatternRules
	}

	d := &Detector{
		config:   cfg,
		patterns: patterns,
	}

	if cfg.EnableML {
		predictor, err := NewMLPredictor(cfg.MLModelPath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ML predictor: %w", err)
		}
		d.mlModel = predictor
	}

	return d, nil
}

func (d *Detector) Detect(content string) []DetectionResult {
	var results []DetectionResult

	// Pattern-based detection
	if d.config.EnablePatterns {
		patternResults := d.detectPatterns(content)
		results = append(results, patternResults...)
	}

	// ML-based detection
	if d.config.EnableML && d.mlModel != nil {
		mlResults := d.detectWithML(content)
		results = append(results, mlResults...)
	}

	return results
}

func (d *Detector) detectPatterns(content string) []DetectionResult {
	var results []DetectionResult

	for _, rule := range d.patterns {
		if strings.Contains(content, rule.Pattern) {
			results = append(results, DetectionResult{
				IsVulnerable:  true,
				Confidence:    1.0,
				Evidence:      rule.Pattern,
				DetectionType: "Pattern",
				Severity:      rule.Severity,
			})
		}
	}

	return results
}

func (d *Detector) detectWithML(content string) []DetectionResult {
	isVulnerable, confidence, evidence := d.mlModel.Predict(content)

	if isVulnerable && confidence >= d.config.MLThreshold {
		severity := "High"
		if confidence < 0.8 {
			severity = "Medium"
		}

		return []DetectionResult{
			{
				IsVulnerable:  true,
				Confidence:    confidence,
				Evidence:      strings.Join(evidence, ", "),
				DetectionType: "ML",
				Severity:      severity,
			},
		}
	}

	return nil
}

// Add a new detection pattern at runtime
func (d *Detector) AddPattern(pattern PatternRule) {
	d.patterns = append(d.patterns, pattern)
}

// Update ML threshold at runtime
func (d *Detector) UpdateMLThreshold(threshold float64) {
	if threshold >= 0 && threshold <= 1 {
		d.config.MLThreshold = threshold
	}
}
