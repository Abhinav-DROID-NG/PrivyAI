package privyai

import (
	"fmt"
	"unicode/utf8"

	"github.com/YOURUSER/privyai/detector"
)

// Engine is the core privacy inspection and redaction engine.
// After initialization with New(), Engine is immutable and safe for concurrent use.
type Engine struct {
	config   Config
	registry *detector.Registry
}

// New creates and initializes a new PrivyAI Engine instance.
func New(cfg Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	reg := detector.NewRegistry()

	// In Phase 1, custom rules are compiled if provided.
	// Built-in detectors will be registered in subsequent phases.
	e := &Engine{
		config:   cfg,
		registry: reg,
	}

	return e, nil
}

// Process inspects and sanitizes plain text using default options.
func (e *Engine) Process(input string) (Result, error) {
	return e.ProcessWithOptions(input, ProcessOptions{
		ContentType: ContentTypePlainText,
	})
}

// ProcessWithOptions inspects and sanitizes text with explicit content type and context hints.
func (e *Engine) ProcessWithOptions(input string, opts ProcessOptions) (Result, error) {
	// 1. Input size validation
	if e.config.MaxInputBytes > 0 && int64(len(input)) > e.config.MaxInputBytes {
		return e.failClosedResult(ErrInputTooLarge)
	}

	// 2. UTF-8 validation
	if !e.config.AllowInvalidUTF8 && !utf8.ValidString(input) {
		return e.failClosedResult(ErrInvalidUTF8)
	}

	// 3. Detector execution
	rawFindings, err := e.registry.RunAll(input)
	if err != nil {
		if e.config.FailClosedOnError {
			return e.failClosedResult(err)
		}
		return Result{}, err
	}

	// In Phase 1 skeleton, findings are unmodified candidates.
	// In later phases: aggregation -> classification -> policy -> redaction will be wired here.
	stats := e.computeStats(rawFindings)
	decision := ActionAllow
	for _, f := range rawFindings {
		decision = MaxAction(decision, f.Action)
	}

	return Result{
		Sanitized:  input,
		Findings:   rawFindings,
		Decision:   decision,
		Blocked:    decision == ActionBlock,
		Restricted: decision == ActionRestrict,
		Stats:      stats,
	}, nil
}

func (e *Engine) computeStats(findings []Finding) Stats {
	stats := Stats{
		TotalFindings:      len(findings),
		FindingsByCategory: make(map[string]int),
		FindingsByTier:     make(map[Tier]int),
	}

	for _, f := range findings {
		stats.FindingsByCategory[f.Category]++
		stats.FindingsByTier[f.Tier]++
	}

	return stats
}

func (e *Engine) failClosedResult(err error) (Result, error) {
	var sanitized string
	if e.config.FailClosedBehavior == FailClosedRedactAll {
		sanitized = "[REDACTED]"
	}
	return Result{
		Sanitized: sanitized,
		Decision:  ActionBlock,
		Blocked:   true,
	}, fmt.Errorf("%w", err)
}
