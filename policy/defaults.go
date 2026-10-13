package policy

import (
	_ "embed"
	"fmt"
)

// DefaultJSON is the strict JSON representation of the built-in policy.
//
//go:embed default_rules.json
var DefaultJSON []byte

// LoadDefault loads the embedded default policy through the strict loader.
func LoadDefault() (Policy, error) {
	p, err := Load(DefaultJSON)
	if err != nil {
		return Policy{}, err
	}
	if len(p.Rules) == 0 {
		return Policy{}, fmt.Errorf("embedded default policy is empty")
	}
	return p, nil
}
