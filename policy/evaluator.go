package policy

import (
	"fmt"

	"github.com/YOURUSER/privyai/detector"
)

// Evaluator evaluates a finding under a context label.
type Evaluator interface {
	Evaluate(detector.Finding, string) (Evaluation, error)
}

// EvaluatorFunc adapts a function to the Evaluator interface.
type EvaluatorFunc func(detector.Finding, string) (Evaluation, error)

// Evaluate calls f.
func (f EvaluatorFunc) Evaluate(finding detector.Finding, context string) (Evaluation, error) {
	return f(finding, context)
}

// EvaluateFailClosed evaluates through evaluator and converts panics or errors
// into the protective action for the finding's tier.
func EvaluateFailClosed(evaluator Evaluator, finding detector.Finding, context string) (result Evaluation, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = failClosed(finding.Tier)
			err = fmt.Errorf("policy evaluator panic")
		}
	}()
	result, err = evaluator.Evaluate(finding, context)
	if err != nil {
		result = failClosed(finding.Tier)
	}
	return result, err
}
