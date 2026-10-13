package privyai

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/YOURUSER/privyai/detector"
	"github.com/YOURUSER/privyai/redactor"
)

// Engine is the core privacy inspection and redaction engine.
// After initialization with New(), Engine is immutable and safe for concurrent use.
type Engine struct {
	config   Config
	registry *detector.Registry
	redactor *redactor.Redactor
}

// New creates and initializes a new PrivyAI Engine instance.
func New(cfg Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	reg := detector.NewRegistry()

	// Register enabled built-in detectors
	if isDetectorEnabled("email", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewEmailDetector()); err != nil {
			return nil, err
		}
	}
	if isDetectorEnabled("phone", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewPhoneDetector()); err != nil {
			return nil, err
		}
	}
	if isDetectorEnabled("ip", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewIPDetector()); err != nil {
			return nil, err
		}
	}

	red := redactor.NewRedactor(cfg.Replacement, cfg.FailClosedBehavior)

	e := &Engine{
		config:   cfg,
		registry: reg,
		redactor: red,
	}

	return e, nil
}

func isDetectorEnabled(name string, enabled []string) bool {
	if enabled == nil {
		return true // nil indicates all built-in detectors enabled
	}
	for _, d := range enabled {
		if d == name {
			return true
		}
	}
	return false
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

	// 4. Default policy assignment for Phase 2:
	// Sensitive findings (e.g. Email / T1+) default to ActionRedact unless policy overrides
	findings := make([]Finding, len(rawFindings))
	decision := ActionAllow

	for i, f := range rawFindings {
		// Default sensitive findings to ActionRedact
		if f.Tier >= TierT1Personal {
			f.Action = ActionRedact
		} else {
			f.Action = ActionAllow
		}
		decision = MaxAction(decision, f.Action)
		findings[i] = f
	}

	// Sort findings deterministically by Start asc, then End asc
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		return findings[i].End < findings[j].End
	})

	// 5. Redaction enforcement
	sanitized, err := e.redactor.Redact(input, findings)
	if err != nil {
		if e.config.FailClosedOnError {
			return e.failClosedResult(err)
		}
		return Result{}, err
	}

	stats := e.computeStats(findings)

	return Result{
		Sanitized:  sanitized,
		Findings:   findings,
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
