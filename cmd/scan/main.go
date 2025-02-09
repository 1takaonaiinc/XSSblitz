package main

import (
"context"
"flag"
"fmt"
"os"
"os/signal"
"path/filepath"
"syscall"
"time"

"github.com/1takaonaiinc/xss-scanner/services/coordinator/pkg/coordinator"
)

func main() {
// Parse command line flags
url := flag.String("url", "", "Target URL to scan")
scanContext := flag.String("context", "html", "Context for payload generation (html, attr, js, url)")
workers := flag.Int("workers", 5, "Number of concurrent workers")
timeout := flag.Duration("timeout", 30*time.Second, "Scan timeout")
modelPath := flag.String("model", "models/default.json", "Path to ML model")
reportDir := flag.String("report-dir", "reports", "Directory for scan reports")
cache := flag.Bool("cache", true, "Enable result caching")
cacheTTL := flag.Duration("cache-ttl", 24*time.Hour, "Cache TTL")

flag.Parse()

if *url == "" {
fmt.Println("Error: URL is required")
flag.Usage()
os.Exit(1)
}

// Ensure report directory exists
if err := os.MkdirAll(*reportDir, 0755); err != nil {
fmt.Printf("Error creating report directory: %v\n", err)
os.Exit(1)
}

// Create coordinator configuration
cfg := coordinator.Config{
MaxWorkers:     *workers,
MaxQueueSize:   *workers * 2,
ScanTimeout:    *timeout,
EnableCache:    *cache,
CacheTTL:       *cacheTTL,
MLModelPath:    *modelPath,
ReportTemplate: filepath.Join("services", "report-service", "templates", "report.html"),
OutputPath:     *reportDir,
}

// Create coordinator
coord, err := coordinator.NewCoordinator(cfg)
if err != nil {
fmt.Printf("Error creating coordinator: %v\n", err)
os.Exit(1)
}

// Create context with cancellation
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Handle interrupt signal
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
go func() {
<-sigChan
fmt.Println("\nReceived interrupt signal. Shutting down...")
cancel()
}()

// Start coordinator
coord.Start(ctx)

fmt.Printf("Starting scan of %s...\n", *url)
startTime := time.Now()

// Submit scan task
completionChan := make(chan struct{})
coord.SubmitTask(*url, *scanContext, nil, completionChan)

// Wait for completion or interruption
select {
case <-ctx.Done():
coord.Stop()
case <-completionChan:
coord.Stop()
}

// Generate reports
if err := coord.GenerateReport(); err != nil {
fmt.Printf("Error generating report: %v\n", err)
os.Exit(1)
}

fmt.Printf("\nScan completed in %s\n", time.Since(startTime))
fmt.Printf("Reports saved to %s\n", *reportDir)
}
