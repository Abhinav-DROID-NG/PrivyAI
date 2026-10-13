package privyai_test

import (
	"testing"
	"unicode/utf8"

	"github.com/YOURUSER/privyai"
	"github.com/YOURUSER/privyai/detector"
	"github.com/YOURUSER/privyai/internal/findings"
	"github.com/YOURUSER/privyai/policy"
	"github.com/YOURUSER/privyai/redactor"
)

func FuzzProcessStructured(f *testing.F) {
	f.Add(`{"password":"value"}`, string(privyai.ContentTypeJSON))
	f.Add("PASSWORD=value\n", string(privyai.ContentTypeEnv))
	f.Add("password: value\n", string(privyai.ContentTypeYAMLLines))
	f.Fuzz(func(t *testing.T, input, contentType string) {
		eng, err := privyai.New(privyai.DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = eng.ProcessWithOptions(input, privyai.ProcessOptions{
			ContentType: privyai.ContentType(contentType),
		})
	})
}

func FuzzPolicyLoad(f *testing.F) {
	f.Add([]byte(`{"rules":[{"category":"email","action":"REDACT"}]}`))
	f.Add([]byte(`{"rules":[]}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = policy.Load(input)
	})
}

func FuzzAggregation(f *testing.F) {
	f.Add(0, 10, 1, 5)
	f.Fuzz(func(t *testing.T, firstStart, firstEnd, secondStart, secondEnd int) {
		findings.Aggregate([]detector.Finding{
			{Category: "a", Start: firstStart, End: firstEnd, Tier: detector.TierT1Personal, Source: "a"},
			{Category: "b", Start: secondStart, End: secondEnd, Tier: detector.TierT2Confidential, Source: "b"},
		}, map[string]int{"a": 1, "b": 2})
	})
}

func FuzzRedactor(f *testing.F) {
	f.Add("alice@example.com")
	f.Add("unicode \u2603")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) == 0 {
			return
		}
		end := len(input)
		for end > 0 && !utf8.RuneStart(input[end-1]) {
			end--
		}
		if end == 0 {
			return
		}
		_, _ = redactor.NewRedactor(redactor.ReplacementConfig{}, redactor.FailClosedNoOutput).Redact(
			input, []detector.Finding{{Category: "fuzz", Start: 0, End: end, Action: detector.ActionRedact}},
		)
	})
}
