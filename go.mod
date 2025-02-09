module github.com/1takaonaiinc/xss-scanner

go 1.21

require (
	github.com/manifoldco/promptui v0.9.0
	golang.org/x/net v0.18.0
)

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	golang.org/x/sys v0.14.0 // indirect
)

replace (
	github.com/1takaonaiinc/xss-scanner/services/coordinator => ./services/coordinator
	github.com/1takaonaiinc/xss-scanner/services/detection-service => ./services/detection-service
	github.com/1takaonaiinc/xss-scanner/services/payload-service => ./services/payload-service
	github.com/1takaonaiinc/xss-scanner/services/report-service => ./services/report-service
	github.com/1takaonaiinc/xss-scanner/services/scanner-service => ./services/scanner-service
)
