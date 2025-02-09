package coordinator

import (
"context"
"fmt"
"os"
"sync"
"time"

"github.com/1takaonaiinc/xss-scanner/services/detection-service/pkg/detector"
"github.com/1takaonaiinc/xss-scanner/services/payload-service/pkg/generator"
"github.com/1takaonaiinc/xss-scanner/services/report-service/pkg/reporter"
"github.com/1takaonaiinc/xss-scanner/services/scanner-service/pkg/scanner"
)

type Config struct {
MaxWorkers     int
MaxQueueSize   int
ScanTimeout    time.Duration
EnableCache    bool
CacheTTL       time.Duration
MLModelPath    string
ReportTemplate string
OutputPath     string
}

type Coordinator struct {
scanner   *scanner.Scanner
detector  *detector.Detector
generator *generator.Generator
reporter  *reporter.Reporter
workQueue chan scanTask
results   chan scanner.ScanResult
workerWg  sync.WaitGroup
cache     *Cache
config    Config
}

type scanTask struct {
URL             string
Context         string
CustomRules     []string
CompletionChan  chan struct{}
}

type Cache struct {
items map[string]cacheItem
mu    sync.RWMutex
ttl   time.Duration
}

type cacheItem struct {
result   scanner.ScanResult
expireAt time.Time
}

func NewCoordinator(cfg Config) (*Coordinator, error) {
// Check if ML model file exists
if _, err := os.Stat(cfg.MLModelPath); os.IsNotExist(err) {
return nil, fmt.Errorf("ML model file not found: %s", cfg.MLModelPath)
}

// Initialize scanner with base configuration
scannerCfg := scanner.Config{
CustomHeaders:    make(map[string]string),
TimeoutSeconds:   int(cfg.ScanTimeout.Seconds()),
MaxConcurrency:   cfg.MaxWorkers,
ExcludePatterns:  []string{},
IncludeParams:    []string{},
InjectedPayloads: []string{}, // Will be updated per scan
}
s := scanner.NewScanner(scannerCfg)

// Initialize detector
detectorCfg := detector.Config{
MLModelPath:    cfg.MLModelPath,
MLThreshold:    0.7,
EnableML:       true,
EnablePatterns: true,
}
d, err := detector.NewDetector(detectorCfg)
if err != nil {
return nil, fmt.Errorf("failed to initialize detector: %w", err)
}

// Initialize payload generator
genCfg := generator.PayloadConfig{
EnableObfuscation: true,
EnableWAFBypass:   true,
}
g := generator.NewGenerator(genCfg)

// Initialize reporter
r := reporter.NewReporter(cfg.OutputPath, cfg.ReportTemplate)

c := &Coordinator{
scanner:   s,
detector:  d,
generator: g,
reporter:  r,
workQueue: make(chan scanTask, cfg.MaxQueueSize),
results:   make(chan scanner.ScanResult, cfg.MaxQueueSize),
config:    cfg,
}

if cfg.EnableCache {
c.cache = &Cache{
items: make(map[string]cacheItem),
ttl:   cfg.CacheTTL,
}
}

return c, nil
}

func (c *Coordinator) Start(ctx context.Context) {
// Start worker pool
for i := 0; i < c.config.MaxWorkers; i++ {
c.workerWg.Add(1)
go c.worker(ctx)
}

// Start result collector
go c.collectResults(ctx)
}

func (c *Coordinator) worker(ctx context.Context) {
defer c.workerWg.Done()

for {
select {
case task, ok := <-c.workQueue:
if !ok {
return
}

// Check cache first if enabled
if c.cache != nil {
if result, found := c.checkCache(task.URL); found {
c.results <- result
if task.CompletionChan != nil {
close(task.CompletionChan)
}
continue
}
}

// Generate context-specific payloads
payloads := c.generator.GeneratePayloads(task.Context)

// Update scanner configuration with the generated payloads
c.scanner.config.InjectedPayloads = payloads

// Start scan with the URL
resultsChan, err := c.scanner.StartScan([]string{task.URL})
if err != nil {
fmt.Printf("Error starting scan for %s: %v\n", task.URL, err)
if task.CompletionChan != nil {
close(task.CompletionChan)
}
continue
}

// Process scan results
for result := range resultsChan {
// Process result through detector
if detections := c.detector.Detect(result.Payload); len(detections) > 0 {
// Update result with detection information
result.Description = detections[0].Evidence
result.Severity = detections[0].Severity
c.results <- result

// Cache result if enabled
if c.cache != nil {
c.cacheResult(task.URL, result)
}
}
}

if task.CompletionChan != nil {
close(task.CompletionChan)
}

case <-ctx.Done():
return
}
}
}

func (c *Coordinator) collectResults(ctx context.Context) {
for {
select {
case result := <-c.results:
c.reporter.AddResult(reporter.ScanResult{
URL:         result.URL,
Severity:    result.Severity,
Description: result.Description,
Payload:     result.Payload,
Timestamp:   time.Now(),
})

case <-ctx.Done():
return
}
}
}

func (c *Coordinator) SubmitTask(url, context string, customRules []string, completionChan chan struct{}) {
c.workQueue <- scanTask{
URL:            url,
Context:        context,
CustomRules:    customRules,
CompletionChan: completionChan,
}
}

func (c *Coordinator) Stop() {
close(c.workQueue)
c.workerWg.Wait()
close(c.results)
}

func (c *Coordinator) GenerateReport() error {
if err := c.reporter.GenerateHTML(); err != nil {
return fmt.Errorf("failed to generate HTML report: %w", err)
}
return c.reporter.GenerateJSON()
}

// Cache methods
func (c *Coordinator) checkCache(url string) (scanner.ScanResult, bool) {
if c.cache == nil {
return scanner.ScanResult{}, false
}

c.cache.mu.RLock()
defer c.cache.mu.RUnlock()

if item, exists := c.cache.items[url]; exists && time.Now().Before(item.expireAt) {
return item.result, true
}
return scanner.ScanResult{}, false
}

func (c *Coordinator) cacheResult(url string, result scanner.ScanResult) {
if c.cache == nil {
return
}

c.cache.mu.Lock()
defer c.cache.mu.Unlock()

c.cache.items[url] = cacheItem{
result:   result,
expireAt: time.Now().Add(c.cache.ttl),
}
}
