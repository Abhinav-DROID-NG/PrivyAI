package detector

// Detector defines the interface that all sensitive data detectors must implement.
type Detector interface {
	// Name returns the unique identifier of the detector (e.g. "email", "ip").
	Name() string

	// Priority defines the precedence when resolving overlapping spans of identical tier and length.
	// Higher numerical priority wins.
	Priority() int

	// Detect scans the input text and returns candidate findings with byte offsets [Start, End).
	Detect(text string) []Finding
}
