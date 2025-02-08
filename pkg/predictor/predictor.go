package predictor

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

type ModelConfig struct {
	Patterns  map[string]float64 `json:"patterns"`
	Contexts  map[string]float64 `json:"contexts"`
	BaseScore float64            `json:"base_score"`
	Threshold float64            `json:"threshold"`
	Keywords  []string           `json:"keywords"`
	CMS       map[string]string  `json:"cms_signatures"`
}

type Predictor struct {
	config ModelConfig
}

type ScoreContribution struct {
	Pattern  string
	Score    float64
	Context  string
	Location string
}

func NewPredictor(modelPath string) (*Predictor, error) {
	if modelPath == "" {
		modelPath = "models/default.json"
	}

	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model file: %v", err)
	}

	var config ModelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse model config: %v", err)
	}

	return &Predictor{config: config}, nil
}

func (p *Predictor) IsXSS(content string) (bool, float64, []ScoreContribution) {
	var totalScore float64 = p.config.BaseScore
	var contributions []ScoreContribution

	// Check for patterns
	for pattern, weight := range p.config.Patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindAllStringIndex(content, -1); matches != nil {
			contextScore := p.getContextScore(content, matches[0][0])
			score := weight * contextScore
			totalScore += score

			contributions = append(contributions, ScoreContribution{
				Pattern:  pattern,
				Score:    score,
				Context:  p.getContext(content, matches[0][0]),
				Location: fmt.Sprintf("offset %d", matches[0][0]),
			})
		}
	}

	// Check for dangerous contexts
	for context, weight := range p.config.Contexts {
		if strings.Contains(content, context) {
			totalScore += weight
			contributions = append(contributions, ScoreContribution{
				Pattern: "context",
				Score:   weight,
				Context: context,
			})
		}
	}

	// Detect CMS if possible
	cms := p.detectCMS(content)
	if cms != "" {
		totalScore *= 1.2 // Increase score for known CMS
		contributions = append(contributions, ScoreContribution{
			Pattern: "cms_detection",
			Score:   totalScore * 0.2,
			Context: fmt.Sprintf("Detected CMS: %s", cms),
		})
	}

	// Check for reflected parameters (basic check)
	if p.hasReflectedParams(content) {
		totalScore *= 1.3 // Increase score for reflected parameters
		contributions = append(contributions, ScoreContribution{
			Pattern: "reflected_params",
			Score:   totalScore * 0.3,
			Context: "Found reflected parameters",
		})
	}

	// Apply keyword-based scoring
	keywordScore := p.getKeywordScore(content)
	if keywordScore > 0 {
		totalScore += keywordScore
		contributions = append(contributions, ScoreContribution{
			Pattern: "keywords",
			Score:   keywordScore,
			Context: "Matched sensitive keywords",
		})
	}

	// Normalize score between 0 and 1
	normalizedScore := 1 / (1 + math.Exp(-totalScore))

	return normalizedScore >= p.config.Threshold, normalizedScore, contributions
}

func (p *Predictor) getContextScore(content string, pos int) float64 {
	// Look for HTML contexts that might increase risk
	beforeContext := content[max(0, pos-50):pos]
	afterContext := content[pos:min(len(content), pos+50)]

	score := 1.0

	// Higher risk contexts
	riskContexts := map[string]float64{
		"<script":     2.0,
		"javascript:": 2.0,
		"onclick":     1.5,
		"onerror":     1.5,
		"href=":       1.3,
		"src=":        1.3,
	}

	for context, multiplier := range riskContexts {
		if strings.Contains(beforeContext, context) || strings.Contains(afterContext, context) {
			score *= multiplier
		}
	}

	return score
}

func (p *Predictor) getContext(content string, pos int) string {
	start := max(0, pos-25)
	end := min(len(content), pos+25)
	return fmt.Sprintf("...%s...", content[start:end])
}

func (p *Predictor) detectCMS(content string) string {
	for cms, signature := range p.config.CMS {
		if strings.Contains(content, signature) {
			return cms
		}
	}
	return ""
}

func (p *Predictor) hasReflectedParams(content string) bool {
	// Look for typical parameter patterns
	patterns := []string{
		`[\?&][^=]+=([^&]+)`,
		`<input[^>]+value=["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(content); matches != nil {
			// Check if the parameter value is reflected in the content
			if len(matches) > 1 && strings.Contains(content, matches[1]) {
				return true
			}
		}
	}

	return false
}

func (p *Predictor) getKeywordScore(content string) float64 {
	var score float64
	for _, keyword := range p.config.Keywords {
		if strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) {
			score += 0.1 // Small boost for each matching keyword
		}
	}
	return score
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
