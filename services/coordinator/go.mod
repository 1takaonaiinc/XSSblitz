module github.com/1takaonaiinc/xss-scanner/services/coordinator

go 1.21

require (
github.com/1takaonaiinc/xss-scanner/services/detection-service v0.0.0
github.com/1takaonaiinc/xss-scanner/services/payload-service v0.0.0
github.com/1takaonaiinc/xss-scanner/services/report-service v0.0.0
github.com/1takaonaiinc/xss-scanner/services/scanner-service v0.0.0
)

replace (
github.com/1takaonaiinc/xss-scanner/services/detection-service => ../detection-service
github.com/1takaonaiinc/xss-scanner/services/payload-service => ../payload-service
github.com/1takaonaiinc/xss-scanner/services/report-service => ../report-service
github.com/1takaonaiinc/xss-scanner/services/scanner-service => ../scanner-service
)
