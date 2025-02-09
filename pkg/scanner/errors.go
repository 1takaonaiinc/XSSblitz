package scanner

import "fmt"

// ScannerError represents a scanner-specific error
type ScannerError struct {
	Type    ErrorType
	Message string
	Err     error
}

type ErrorType int

const (
	ErrorTypeInvalidConfig ErrorType = iota
	ErrorTypeHTTPRequest
	ErrorTypeNetworkFailure
	ErrorTypeInvalidResponse
	ErrorTypeMLPrediction
	ErrorTypeTimeout
)

// Error type strings for better error messaging
func (e ErrorType) String() string {
	switch e {
	case ErrorTypeInvalidConfig:
		return "invalid configuration"
	case ErrorTypeHTTPRequest:
		return "HTTP request error"
	case ErrorTypeNetworkFailure:
		return "network failure"
	case ErrorTypeInvalidResponse:
		return "invalid response"
	case ErrorTypeMLPrediction:
		return "ML prediction error"
	case ErrorTypeTimeout:
		return "operation timeout"
	default:
		return "unknown error"
	}
}

func (e *ScannerError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ScannerError) Unwrap() error {
	return e.Err
}

// NewScannerError creates a new ScannerError
func NewScannerError(errType ErrorType, message string, err error) *ScannerError {
	return &ScannerError{
		Type:    errType,
		Message: message,
		Err:     err,
	}
}
