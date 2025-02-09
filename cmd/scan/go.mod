module github.com/1takaonaiinc/xss-scanner/cmd/scan

go 1.21

require (
github.com/1takaonaiinc/xss-scanner/services/coordinator v0.0.0
)

replace (
github.com/1takaonaiinc/xss-scanner/services/coordinator => ../../services/coordinator
github.com/1takaonaiinc/xss-scanner/services/detection-service => ../../services/detection-service
github.com/1takaonaiinc/xss-scanner/services/payload-service => ../../services/payload-service
github.com/1takaonaiinc/xss-scanner/services/report-service => ../../services/report-service
github.com/1takaonaiinc/xss-scanner/services/scanner-service => ../../services/scanner-service
)
