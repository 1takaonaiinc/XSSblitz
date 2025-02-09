package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

// ScanResult represents a single vulnerability finding
type ScanResult struct {
	URL         string    `json:"url"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Payload     string    `json:"payload"`
	Context     string    `json:"context"`
	Evidence    string    `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// Report represents the complete scan report
type Report struct {
	ScanID        string       `json:"scan_id"`
	Target        string       `json:"target"`
	StartTime     time.Time    `json:"start_time"`
	EndTime       time.Time    `json:"end_time"`
	Results       []ScanResult `json:"results"`
	Summary       Summary      `json:"summary"`
	Configuration Config       `json:"configuration"`
}

// Summary contains scan statistics
type Summary struct {
	TotalURLs        int            `json:"total_urls"`
	ScannedURLs      int            `json:"scanned_urls"`
	VulnerableURLs   int            `json:"vulnerable_urls"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	PayloadStats     map[string]int `json:"payload_stats"`
	DetectionMethods map[string]int `json:"detection_methods"`
}

// Config represents the scan configuration
type Config struct {
	EnableML        bool     `json:"enable_ml"`
	EnableWAFBypass bool     `json:"enable_waf_bypass"`
	CustomPayloads  []string `json:"custom_payloads"`
	ExcludedURLs    []string `json:"excluded_urls"`
	IncludedParams  []string `json:"included_params"`
	MaxConcurrency  int      `json:"max_concurrency"`
	ScanDepth       int      `json:"scan_depth"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
}

// Reporter handles report generation and storage
type Reporter struct {
	currentReport *Report
	outputPath    string
	templatePath  string
}

func NewReporter(outputPath, templatePath string) *Reporter {
	return &Reporter{
		outputPath:   outputPath,
		templatePath: templatePath,
		currentReport: &Report{
			StartTime: time.Now(),
			Summary: Summary{
				SeverityCounts:   make(map[string]int),
				PayloadStats:     make(map[string]int),
				DetectionMethods: make(map[string]int),
			},
		},
	}
}

// InitializeScan starts a new scan report
func (r *Reporter) InitializeScan(target string, config Config) {
	r.currentReport = &Report{
		ScanID:        fmt.Sprintf("scan_%d", time.Now().Unix()),
		Target:        target,
		StartTime:     time.Now(),
		Configuration: config,
		Results:       make([]ScanResult, 0),
		Summary: Summary{
			SeverityCounts:   make(map[string]int),
			PayloadStats:     make(map[string]int),
			DetectionMethods: make(map[string]int),
		},
	}
}

// AddResult adds a new finding to the report
func (r *Reporter) AddResult(result ScanResult) {
	r.currentReport.Results = append(r.currentReport.Results, result)
	r.updateSummary(result)
}

func (r *Reporter) updateSummary(result ScanResult) {
	// Update severity counts
	r.currentReport.Summary.SeverityCounts[result.Severity]++

	// Update payload stats if available
	if result.Payload != "" {
		r.currentReport.Summary.PayloadStats[result.Context]++
	}

	// Count unique vulnerable URLs
	urlMap := make(map[string]bool)
	for _, res := range r.currentReport.Results {
		urlMap[res.URL] = true
	}
	r.currentReport.Summary.VulnerableURLs = len(urlMap)
}

// GenerateHTML generates an interactive HTML report
func (r *Reporter) GenerateHTML() error {
	r.currentReport.EndTime = time.Now()

	tmpl, err := template.ParseFiles(r.templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, r.currentReport); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	htmlPath := fmt.Sprintf("%s/%s_report.html", r.outputPath, r.currentReport.ScanID)
	if err := os.WriteFile(htmlPath, htmlBuffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	return nil
}

// GenerateJSON generates a JSON report
func (r *Reporter) GenerateJSON() error {
	r.currentReport.EndTime = time.Now()

	jsonData, err := json.MarshalIndent(r.currentReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	jsonPath := fmt.Sprintf("%s/%s_report.json", r.outputPath, r.currentReport.ScanID)
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// GetSummary returns the current scan summary
func (r *Reporter) GetSummary() Summary {
	return r.currentReport.Summary
}

// GetResults returns all results for the current scan
func (r *Reporter) GetResults() []ScanResult {
	return r.currentReport.Results
}

// FilterResults returns results matching given criteria
func (r *Reporter) FilterResults(severity string, minConfidence float64) []ScanResult {
	var filtered []ScanResult
	for _, result := range r.currentReport.Results {
		if severity != "" && result.Severity != severity {
			continue
		}
		filtered = append(filtered, result)
	}
	return filtered
}

// UpdateConfig updates the scan configuration
func (r *Reporter) UpdateConfig(config Config) {
	r.currentReport.Configuration = config
}

// SetScannedURLs sets the total number of scanned URLs
func (r *Reporter) SetScannedURLs(total, scanned int) {
	r.currentReport.Summary.TotalURLs = total
	r.currentReport.Summary.ScannedURLs = scanned
}
