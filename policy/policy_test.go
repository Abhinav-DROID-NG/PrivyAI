package policy

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/YOURUSER/privyai/detector"
)

func TestDefaultJSONEquivalent(t *testing.T) {
	loaded, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(loaded, Default()) {
		t.Fatalf("embedded policy differs from built-in policy")
	}
}

func TestRepositoryDefaultJSONLoads(t *testing.T) {
	data, err := os.ReadFile("../configs/default_rules.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, Default()) {
		t.Fatal("repository default policy differs from built-in policy")
	}
}

func TestContextAndPrecedence(t *testing.T) {
	p := Default()
	f := detector.Finding{Category: "email", Tier: detector.TierT1Personal}
	external, err := p.Evaluate(f, "external_transmission")
	if err != nil || external.Action != detector.ActionRedact {
		t.Fatalf("external evaluation = %#v, %v", external, err)
	}
	local, err := p.Evaluate(f, "local_only")
	if err != nil || local.Action != detector.ActionAllow {
		t.Fatalf("local evaluation = %#v, %v", local, err)
	}
}

func TestStrictLoader(t *testing.T) {
	for name, input := range map[string]string{
		"unknown field": `{"rules":[{"action":"ALLOW","bogus":true}]}`,
		"numeric tier":  `{"rules":[{"min_tier":3,"action":"ALLOW"}]}`,
		"bad action":    `{"rules":[{"action":"NOPE"}]}`,
		"trailing":      `{"rules":[{"action":"ALLOW","category":"x"}]} garbage`,
		"empty":         `{"rules":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(input)); err == nil || !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("expected ErrInvalidRule, got %v", err)
			}
		})
	}
}

func TestRestrictConditionsSortedAndDeduplicated(t *testing.T) {
	p := Policy{Rules: []Rule{{Category: "secret", Action: detector.ActionRestrict, Conditions: []string{"b", "a", "b"}}}}
	got, err := p.Evaluate(detector.Finding{Category: "secret"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Conditions, []string{"a", "b"}) {
		t.Fatalf("conditions = %#v", got.Conditions)
	}
}

func TestPrecedenceScenarios(t *testing.T) {
	tier := func(value detector.Tier) *detector.Tier { return &value }
	priority := func(value int) *int { return &value }
	tests := []struct {
		name   string
		rules  []Rule
		f      detector.Finding
		ctx    string
		action detector.Action
	}{
		{"exact beats glob", []Rule{{Category: "*", Action: detector.ActionAllow}, {Category: "email", Action: detector.ActionRedact}}, detector.Finding{Category: "email"}, "", detector.ActionRedact},
		{"glob beats tier", []Rule{{MinTier: tier(detector.TierT1Personal), Action: detector.ActionAllow}, {Category: "e*", Action: detector.ActionBlock}}, detector.Finding{Category: "email", Tier: detector.TierT1Personal}, "", detector.ActionBlock},
		{"tier beats default", []Rule{{Action: detector.ActionAllow}, {MinTier: tier(detector.TierT2Confidential), Action: detector.ActionRedact}}, detector.Finding{Tier: detector.TierT2Confidential}, "", detector.ActionRedact},
		{"priority wins", []Rule{{Category: "email", Action: detector.ActionAllow, Priority: priority(1)}, {Category: "email", Action: detector.ActionBlock, Priority: priority(2)}}, detector.Finding{Category: "email"}, "", detector.ActionBlock},
		{"negative priority still explicit", []Rule{{Category: "email", Action: detector.ActionAllow}, {Category: "email", Action: detector.ActionBlock, Priority: priority(-1)}}, detector.Finding{Category: "email"}, "", detector.ActionBlock},
		{"protective tie block", []Rule{{Category: "email", Action: detector.ActionRedact}, {Category: "email", Action: detector.ActionBlock}}, detector.Finding{Category: "email"}, "", detector.ActionBlock},
		{"protective tie restrict", []Rule{{Category: "email", Action: detector.ActionAllow}, {Category: "email", Action: detector.ActionRestrict}}, detector.Finding{Category: "email"}, "", detector.ActionRestrict},
		{"protective tie redact", []Rule{{Category: "email", Action: detector.ActionAllow}, {Category: "email", Action: detector.ActionRedact}}, detector.Finding{Category: "email"}, "", detector.ActionRedact},
		{"index tie", []Rule{{Category: "email", Action: detector.ActionRedact}, {Category: "email", Action: detector.ActionRedact, ReplacementLabel: "later"}}, detector.Finding{Category: "email"}, "", detector.ActionRedact},
		{"context match", []Rule{{Category: "email", Context: "local_only", Action: detector.ActionAllow}, {Category: "email", Action: detector.ActionRedact}}, detector.Finding{Category: "email"}, "local_only", detector.ActionRedact},
		{"context protective", []Rule{{Category: "email", Context: "external_transmission", Action: detector.ActionRedact}, {Category: "email", Action: detector.ActionAllow}}, detector.Finding{Category: "email"}, "external_transmission", detector.ActionRedact},
		{"min bound", []Rule{{MinTier: tier(detector.TierT2Confidential), Action: detector.ActionBlock}}, detector.Finding{Tier: detector.TierT2Confidential}, "", detector.ActionBlock},
		{"max bound", []Rule{{MaxTier: tier(detector.TierT1Personal), Action: detector.ActionBlock}}, detector.Finding{Tier: detector.TierT1Personal}, "", detector.ActionBlock},
		{"range bound", []Rule{{MinTier: tier(detector.TierT1Personal), MaxTier: tier(detector.TierT2Confidential), Action: detector.ActionRestrict}}, detector.Finding{Tier: detector.TierT2Confidential}, "", detector.ActionRestrict},
		{"question glob", []Rule{{Category: "ip?", Action: detector.ActionBlock}}, detector.Finding{Category: "ips"}, "", detector.ActionBlock},
		{"character glob", []Rule{{Category: "[es]mail", Action: detector.ActionBlock}}, detector.Finding{Category: "email"}, "", detector.ActionBlock},
		{"unmatched falls closed", []Rule{{Category: "email", Action: detector.ActionAllow}}, detector.Finding{Category: "secret", Tier: detector.TierT3Restricted}, "", detector.ActionBlock},
		{"t0 allow", []Rule{{MinTier: tier(detector.TierT0Public), MaxTier: tier(detector.TierT0Public), Action: detector.ActionAllow}}, detector.Finding{Tier: detector.TierT0Public}, "", detector.ActionAllow},
		{"t1 redact", []Rule{{MinTier: tier(detector.TierT1Personal), MaxTier: tier(detector.TierT1Personal), Action: detector.ActionRedact}}, detector.Finding{Tier: detector.TierT1Personal}, "", detector.ActionRedact},
		{"t2 restrict", []Rule{{MinTier: tier(detector.TierT2Confidential), MaxTier: tier(detector.TierT2Confidential), Action: detector.ActionRestrict}}, detector.Finding{Tier: detector.TierT2Confidential}, "", detector.ActionRestrict},
		{"t3 redact", []Rule{{MinTier: tier(detector.TierT3Restricted), MaxTier: tier(detector.TierT3Restricted), Action: detector.ActionRedact}}, detector.Finding{Tier: detector.TierT3Restricted}, "", detector.ActionRedact},
		{"t4 block", []Rule{{MinTier: tier(detector.TierT4Critical), MaxTier: tier(detector.TierT4Critical), Action: detector.ActionBlock}}, detector.Finding{Tier: detector.TierT4Critical}, "", detector.ActionBlock},
		{"exact long category", []Rule{{Category: "database_*", Action: detector.ActionRedact}, {Category: "database_credentials", Action: detector.ActionBlock}}, detector.Finding{Category: "database_credentials"}, "", detector.ActionBlock},
		{"priority overrides specificity", []Rule{{Category: "email", Action: detector.ActionBlock}, {Action: detector.ActionAllow, Priority: priority(9)}}, detector.Finding{Category: "email"}, "", detector.ActionAllow},
		{"priority tie uses specificity", []Rule{{Category: "*", Action: detector.ActionAllow, Priority: priority(1)}, {Category: "email", Action: detector.ActionRedact, Priority: priority(1)}}, detector.Finding{Category: "email"}, "", detector.ActionRedact},
		{"priority tie protective", []Rule{{Category: "email", Action: detector.ActionRedact, Priority: priority(1)}, {Category: "email", Action: detector.ActionBlock, Priority: priority(1)}}, detector.Finding{Category: "email"}, "", detector.ActionBlock},
	}

	if len(tests) < 25 {
		t.Fatalf("test table has %d scenarios, want at least 25", len(tests))
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (Policy{Rules: test.rules}).Evaluate(test.f, test.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != test.action {
				t.Fatalf("got %s, want %s", got.Action, test.action)
			}
		})
	}
}

func TestEvaluateFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		tier   detector.Tier
		action detector.Action
	}{
		{"t2 error", detector.TierT2Confidential, detector.ActionRedact},
		{"t3 error", detector.TierT3Restricted, detector.ActionBlock},
		{"t4 panic", detector.TierT4Critical, detector.ActionBlock},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := EvaluatorFunc(func(detector.Finding, string) (Evaluation, error) {
				if test.name == "t4 panic" {
					panic("must not escape")
				}
				return Evaluation{}, errors.New("evaluation failed")
			})
			result, err := EvaluateFailClosed(evaluator, detector.Finding{Tier: test.tier}, "")
			if err == nil {
				t.Fatal("expected evaluator error")
			}
			if result.Action != test.action {
				t.Fatalf("got %s, want %s", result.Action, test.action)
			}
		})
	}
}
