package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/1takaonaiinc/xss-scanner/pkg/payloadfetcher"
)

const (
	defaultModelPath = "../../models/default.json"
	portSwiggerURL   = "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
)

func main() {
	// Create payload fetcher
	fetcher := payloadfetcher.NewPayloadFetcher(portSwiggerURL)

	// Fetch payloads
	payloads, err := fetcher.FetchPayloads()
	if err != nil {
		fmt.Printf("Error fetching payloads: %v\n", err)
		os.Exit(1)
	}

	if len(payloads) == 0 {
		fmt.Println("No payloads found!")
		os.Exit(1)
	}

	// Read existing model file
	modelPath, err := filepath.Abs(defaultModelPath)
	if err != nil {
		fmt.Printf("Error resolving model path: %v\n", err)
		os.Exit(1)
	}

	var config map[string]interface{}
	data, err := os.ReadFile(modelPath)
	if err != nil {
		fmt.Printf("Error reading model file: %v\n", err)
		os.Exit(1)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Printf("Error parsing model file: %v\n", err)
		os.Exit(1)
	}

	// Update patterns in the config
	patterns := make(map[string]float64)
	for _, payload := range payloads {
		patterns[payload] = 1.0 // Assign maximum weight to new patterns
	}

	// Merge with existing patterns if any
	if existingPatterns, ok := config["patterns"].(map[string]interface{}); ok {
		for pattern, weight := range existingPatterns {
			if w, ok := weight.(float64); ok {
				if _, exists := patterns[pattern]; !exists {
					patterns[pattern] = w
				}
			}
		}
	}

	// Update config with new patterns
	config["patterns"] = patterns

	// Write updated config back to file
	updatedData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		fmt.Printf("Error marshaling updated config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(modelPath, updatedData, 0644); err != nil {
		fmt.Printf("Error writing updated config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully updated default model with %d patterns!\n", len(patterns))

	// Print a sample of new patterns
	fmt.Println("\nSample of updated patterns:")
	count := 0
	for pattern := range patterns {
		if count >= 5 {
			break
		}
		fmt.Printf("- %s\n", pattern)
		count++
	}
}
