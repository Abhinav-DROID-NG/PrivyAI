package privyai

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/YOURUSER/privyai/classifier"
	"github.com/YOURUSER/privyai/detector"
	"github.com/YOURUSER/privyai/internal/findings"
	"github.com/YOURUSER/privyai/policy"
	"github.com/YOURUSER/privyai/redactor"
	"github.com/YOURUSER/privyai/structured"
	"strings"
)

// Engine is the core privacy inspection and redaction engine.
// After initialization with New(), Engine is immutable and safe for concurrent use.
type Engine struct {
	config     Config
	registry   *detector.Registry
	redactor   *redactor.Redactor
	classifier *classifier.Classifier
	policy     policy.Evaluator
}

// New creates and initializes a new PrivyAI Engine instance.
func New(cfg Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	customTiers := make(map[string]Tier, len(cfg.CustomRules))
	for _, rule := range cfg.CustomRules {
		customTiers[rule.Category] = rule.Tier
	}
	classifierEngine, err := classifier.NewWithCustom(cfg.DefaultTier, cfg.TierOverrides, customTiers)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	activePolicy := policy.Default()
	if len(cfg.PolicyJSON) > 0 {
		activePolicy, err = policy.Load(cfg.PolicyJSON)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
		}
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
	if isDetectorEnabled("secrets", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewSecretsDetector(cfg.EntropyDetection, cfg.EntropyThreshold)); err != nil {
			return nil, err
		}
	}
	if isDetectorEnabled("financial", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewFinancialDetector()); err != nil {
			return nil, err
		}
	}
	if isDetectorEnabled("identifiers", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewIdentifiersDetector(cfg.IdentifierJurisdictions)); err != nil {
			return nil, err
		}
	}
	if isDetectorEnabled("database", cfg.EnabledDetectors) {
		if err := reg.Register(detector.NewDatabaseDetector(cfg.DatabaseRedactMode)); err != nil {
			return nil, err
		}
	}
	if len(cfg.CustomRules) > 0 {
		customDet, err := detector.NewCustomDetector(cfg.CustomRules)
		if err != nil {
			return nil, err
		}
		if err := reg.Register(customDet); err != nil {
			return nil, err
		}
	}

	red := redactor.NewRedactor(cfg.Replacement, cfg.FailClosedBehavior)

	e := &Engine{
		config:     cfg,
		registry:   reg,
		redactor:   red,
		classifier: classifierEngine,
		policy:     activePolicy,
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
		ContentType:  ContentTypePlainText,
		ContextLabel: "external_transmission",
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
	structuredFindings, structuredFallback, structuredErr := e.scanStructured(input, opts.ContentType)
	if structuredErr != nil {
		return e.failClosedResult(structuredErr)
	}
	rawFindings = append(rawFindings, structuredFindings...)

	// 4. Aggregation: deduplicate and resolve overlaps deterministically
	aggregated := findings.Aggregate(rawFindings, e.registry.Priorities())

	// 5. Classify and evaluate policy.
	processedFindings := e.classifier.ClassifyAll(aggregated)
	decision := ActionAllow
	var conditions []string
	for i := range processedFindings {
		evaluation, evalErr := policy.EvaluateFailClosed(e.policy, processedFindings[i], opts.ContextLabel)
		if evalErr != nil {
			return e.failClosedResult(evalErr)
		}
		processedFindings[i].Action = evaluation.Action
		decision = MaxAction(decision, evaluation.Action)
		conditions = append(conditions, evaluation.Conditions...)
	}
	conditions = uniqueStrings(conditions)

	// 6. Redaction enforcement. BLOCK never returns sanitized content.
	if decision == ActionBlock {
		return Result{
			Findings: processedFindings, Decision: decision, Blocked: true,
			Conditions: conditions, StructuredFallback: structuredFallback,
			Stats: e.computeStats(processedFindings),
		}, nil
	}
	sanitized, err := e.redactor.Redact(input, processedFindings)
	if err != nil {
		if e.config.FailClosedOnError {
			return e.failClosedResult(err)
		}
		return Result{}, err
	}

	stats := e.computeStats(processedFindings)

	return Result{
		Sanitized:  sanitized,
		Findings:   processedFindings,
		Decision:   decision,
		Restricted: decision == ActionRestrict,
		Conditions: conditions, StructuredFallback: structuredFallback, Stats: stats,
	}, nil
}

func (e *Engine) scanStructured(input string, contentType ContentType) ([]Finding, bool, error) {
	format := structured.Format("")
	switch contentType {
	case ContentTypeJSON:
		format = structured.JSON
	case ContentTypeEnv:
		format = structured.Env
	case ContentTypeYAMLLines:
		format = structured.YAMLLines
	case ContentTypeAuto:
		trimmed := strings.TrimSpace(input)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			format = structured.JSON
		}
	default:
		return nil, false, nil
	}
	if format == "" {
		return nil, false, nil
	}
	return structured.Scan(input, format, e.config.StructuredMaxDepth)
}

func uniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
