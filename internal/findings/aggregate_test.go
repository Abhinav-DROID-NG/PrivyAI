package findings

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

func TestAggregateTableDriven(t *testing.T) {
	priorities := map[string]int{
		"db_detector":     95,
		"secrets":         90,
		"financial":       85,
		"identifiers":     80,
		"email":           80,
		"phone":           70,
		"ip":              60,
		"high_priority":   100,
		"medium_priority": 50,
		"low_priority":    10,
	}

	tests := []struct {
		name       string
		candidates []detector.Finding
		expected   []detector.Finding
	}{
		{
			name: "Scenario 1: Exact duplicates merged keeping highest confidence",
			candidates: []detector.Finding{
				{Category: "email", Start: 0, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceLow, Source: "email"},
				{Category: "email", Start: 0, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email", Validated: true},
			},
			expected: []detector.Finding{
				{Category: "email", Start: 0, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email", Validated: true},
			},
		},
		{
			name: "Scenario 2: Partial overlap - higher tier wins (T3 vs T1)",
			candidates: []detector.Finding{
				{Category: "phone", Start: 10, End: 22, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "ssn", Start: 15, End: 26, Tier: detector.TierT3Restricted, Source: "identifiers"},
			},
			expected: []detector.Finding{
				{Category: "ssn", Start: 15, End: 26, Tier: detector.TierT3Restricted, Source: "identifiers"},
			},
		},
		{
			name: "Scenario 3: Partial overlap - higher tier wins (T4 vs T2)",
			candidates: []detector.Finding{
				{Category: "internal_ip", Start: 5, End: 20, Tier: detector.TierT2Confidential, Source: "ip"},
				{Category: "database_credentials", Start: 15, End: 30, Tier: detector.TierT4Critical, Source: "db_detector"},
			},
			expected: []detector.Finding{
				{Category: "database_credentials", Start: 15, End: 30, Tier: detector.TierT4Critical, Source: "db_detector"},
			},
		},
		{
			name: "Scenario 4: Nested overlap - outer higher tier (T4 database enclosing T1 email)",
			candidates: []detector.Finding{
				{Category: "email", Start: 20, End: 35, Tier: detector.TierT1Personal, Source: "email"},
				{Category: "database_credentials", Start: 10, End: 50, Tier: detector.TierT4Critical, Source: "db_detector"},
			},
			expected: []detector.Finding{
				{Category: "database_credentials", Start: 10, End: 50, Tier: detector.TierT4Critical, Source: "db_detector"},
			},
		},
		{
			name: "Scenario 5: Nested overlap - inner higher tier (T3 card inside T1 phone candidate)",
			candidates: []detector.Finding{
				{Category: "phone", Start: 5, End: 35, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "payment_card", Start: 10, End: 26, Tier: detector.TierT3Restricted, Source: "financial"},
			},
			expected: []detector.Finding{
				{Category: "payment_card", Start: 10, End: 26, Tier: detector.TierT3Restricted, Source: "financial"},
			},
		},
		{
			name: "Scenario 6: Equal tier partial overlap - longer span wins",
			candidates: []detector.Finding{
				{Category: "secret", Start: 10, End: 25, Tier: detector.TierT3Restricted, Source: "secrets"}, // len 15
				{Category: "secret", Start: 20, End: 40, Tier: detector.TierT3Restricted, Source: "secrets"}, // len 20
			},
			expected: []detector.Finding{
				{Category: "secret", Start: 20, End: 40, Tier: detector.TierT3Restricted, Source: "secrets"},
			},
		},
		{
			name: "Scenario 7: Equal tier nested overlap - longer span wins",
			candidates: []detector.Finding{
				{Category: "secret", Start: 15, End: 25, Tier: detector.TierT3Restricted, Source: "secrets"}, // len 10
				{Category: "secret", Start: 10, End: 30, Tier: detector.TierT3Restricted, Source: "secrets"}, // len 20
			},
			expected: []detector.Finding{
				{Category: "secret", Start: 10, End: 30, Tier: detector.TierT3Restricted, Source: "secrets"},
			},
		},
		{
			name: "Scenario 8: Equal tier and length - higher detector priority wins",
			candidates: []detector.Finding{
				{Category: "token_low", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "low_priority"},
				{Category: "token_high", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "high_priority"},
			},
			expected: []detector.Finding{
				{Category: "token_high", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "high_priority"},
			},
		},
		{
			name: "Scenario 9: Equal tier, length, priority - smaller Category wins",
			candidates: []detector.Finding{
				{Category: "zebra", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "medium_priority"},
				{Category: "alpha", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "medium_priority"},
			},
			expected: []detector.Finding{
				{Category: "alpha", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "medium_priority"},
			},
		},
		{
			name: "Scenario 10: Equal tier, length, priority, category - smaller Source name wins",
			candidates: []detector.Finding{
				{Category: "token", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "source_z"},
				{Category: "token", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "source_a"},
			},
			expected: []detector.Finding{
				{Category: "token", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "source_a"},
			},
		},
		{
			name: "Scenario 11: Adjacent spans - both preserved without merge",
			candidates: []detector.Finding{
				{Category: "token_b", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "secrets"},
				{Category: "token_a", Start: 0, End: 10, Tier: detector.TierT3Restricted, Source: "secrets"},
			},
			expected: []detector.Finding{
				{Category: "token_a", Start: 0, End: 10, Tier: detector.TierT3Restricted, Source: "secrets"},
				{Category: "token_b", Start: 10, End: 20, Tier: detector.TierT3Restricted, Source: "secrets"},
			},
		},
		{
			name: "Scenario 12: Multi-chain overlap - central high tier eliminates adjacent lower tiers",
			candidates: []detector.Finding{
				{Category: "phone", Start: 0, End: 12, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "private_key", Start: 10, End: 25, Tier: detector.TierT4Critical, Source: "secrets"},
				{Category: "email", Start: 22, End: 35, Tier: detector.TierT1Personal, Source: "email"},
			},
			expected: []detector.Finding{
				{Category: "private_key", Start: 10, End: 25, Tier: detector.TierT4Critical, Source: "secrets"},
			},
		},
		{
			name: "Scenario 13: Multi-chain overlap - outer high tiers eliminate central low tier",
			candidates: []detector.Finding{
				{Category: "ssn", Start: 0, End: 11, Tier: detector.TierT3Restricted, Source: "identifiers"},
				{Category: "phone", Start: 9, End: 22, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "card", Start: 20, End: 36, Tier: detector.TierT3Restricted, Source: "financial"},
			},
			expected: []detector.Finding{
				{Category: "ssn", Start: 0, End: 11, Tier: detector.TierT3Restricted, Source: "identifiers"},
				{Category: "card", Start: 20, End: 36, Tier: detector.TierT3Restricted, Source: "financial"},
			},
		},
		{
			name: "Scenario 14: Multiple duplicates with 3 confidence levels merged",
			candidates: []detector.Finding{
				{Category: "email", Start: 5, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceLow, Source: "email"},
				{Category: "email", Start: 5, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceMedium, Source: "email"},
				{Category: "email", Start: 5, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email", Validated: true},
			},
			expected: []detector.Finding{
				{Category: "email", Start: 5, End: 15, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email", Validated: true},
			},
		},
		{
			name: "Scenario 15: One large T4 span enclosing multiple smaller T1 spans",
			candidates: []detector.Finding{
				{Category: "database_credentials", Start: 0, End: 100, Tier: detector.TierT4Critical, Source: "db_detector"},
				{Category: "email", Start: 10, End: 25, Tier: detector.TierT1Personal, Source: "email"},
				{Category: "phone", Start: 30, End: 45, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "ip", Start: 50, End: 65, Tier: detector.TierT1Personal, Source: "ip"},
			},
			expected: []detector.Finding{
				{Category: "database_credentials", Start: 0, End: 100, Tier: detector.TierT4Critical, Source: "db_detector"},
			},
		},
		{
			name: "Scenario 16: Disjoint findings ordered by Start ascending",
			candidates: []detector.Finding{
				{Category: "ip", Start: 50, End: 60, Tier: detector.TierT1Personal, Source: "ip"},
				{Category: "email", Start: 0, End: 15, Tier: detector.TierT1Personal, Source: "email"},
				{Category: "phone", Start: 25, End: 35, Tier: detector.TierT1Personal, Source: "phone"},
			},
			expected: []detector.Finding{
				{Category: "email", Start: 0, End: 15, Tier: detector.TierT1Personal, Source: "email"},
				{Category: "phone", Start: 25, End: 35, Tier: detector.TierT1Personal, Source: "phone"},
				{Category: "ip", Start: 50, End: 60, Tier: detector.TierT1Personal, Source: "ip"},
			},
		},
		{
			name:       "Scenario 17: Empty candidate list",
			candidates: nil,
			expected:   nil,
		},
		{
			name: "Scenario 18: Single candidate preserved",
			candidates: []detector.Finding{
				{Category: "email", Start: 5, End: 20, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email"},
			},
			expected: []detector.Finding{
				{Category: "email", Start: 5, End: 20, Tier: detector.TierT1Personal, Confidence: detector.ConfidenceHigh, Source: "email"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := Aggregate(tt.candidates, priorities)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("\nexpected: %+v\ngot:      %+v", tt.expected, actual)
			}
		})
	}
}

// Property-based test: randomized input candidates must always result in
// strictly sorted, non-overlapping findings, and aggregation must be idempotent.
func TestAggregatePropertyNonOverlappingAndSorted(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	priorities := map[string]int{
		"detA": 10,
		"detB": 50,
		"detC": 90,
	}
	sources := []string{"detA", "detB", "detC"}
	categories := []string{"catA", "catB", "catC"}

	for trial := 0; trial < 200; trial++ {
		numFindings := rng.Intn(50) + 1
		candidates := make([]detector.Finding, numFindings)

		for i := 0; i < numFindings; i++ {
			start := rng.Intn(200)
			spanLen := rng.Intn(30) + 1
			end := start + spanLen
			tier := detector.Tier(rng.Intn(5))
			conf := detector.Confidence(rng.Intn(3) + 1)
			src := sources[rng.Intn(len(sources))]
			cat := categories[rng.Intn(len(categories))]

			candidates[i] = detector.Finding{
				Category:   cat,
				Start:      start,
				End:        end,
				Tier:       tier,
				Source:     src,
				Confidence: conf,
				Validated:  rng.Intn(2) == 1,
			}
		}

		result := Aggregate(candidates, priorities)

		// Property 1: Output is strictly sorted by Start ascending
		for i := 1; i < len(result); i++ {
			if result[i].Start < result[i-1].Start {
				t.Fatalf("trial %d: output not sorted: finding %d (start %d) < finding %d (start %d)",
					trial, i, result[i].Start, i-1, result[i-1].Start)
			}
		}

		// Property 2: No two output findings overlap
		for i := 1; i < len(result); i++ {
			if result[i].Start < result[i-1].End {
				t.Fatalf("trial %d: findings overlap! [%d, %d) and [%d, %d)",
					trial, result[i-1].Start, result[i-1].End, result[i].Start, result[i].End)
			}
		}

		// Property 3: Idempotence: Aggregate(Aggregate(x)) == Aggregate(x)
		secondPass := Aggregate(result, priorities)
		if !reflect.DeepEqual(result, secondPass) {
			t.Fatalf("trial %d: aggregation is not idempotent!\nfirst:  %+v\nsecond: %+v",
				trial, result, secondPass)
		}
	}
}
