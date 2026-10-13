package findings

import (
	"sort"

	"github.com/YOURUSER/privyai/detector"
)

// Aggregate merges exact duplicates and resolves partial and nested overlaps
// deterministically according to PrivyAI resolution precedence rules.
//
// Resolution order:
//  1. Exact duplicates (same Start, End, and Category):
//     Merged into a single finding keeping the highest Confidence,
//     logical OR of Validated flags, and the highest Tier.
//  2. Overlapping findings (partial or nested/contained):
//     Selected greedily according to strict total ordering:
//     a. Higher Tier wins (e.g. T4 database credentials beats T1 email).
//     b. If Tiers are equal, longer span wins (e.g. outer match beats inner match).
//     c. If span lengths are equal, higher detector priority wins.
//     d. If detector priorities are equal, lexicographically smaller Category wins.
//     e. Finally, lexicographically smaller Source name wins.
//
// Contained spans (nested matches):
// A contained span is an overlap where one span [s1, e1) is entirely within [s2, e2).
// Contained spans are resolved by the exact same rule: higher Tier wins.
//   - If the outer span has higher Tier (e.g. database credentials T4 enclosing an email T1),
//     the outer span is retained and the inner span is suppressed.
//   - If the inner span has higher Tier (e.g. payment card T3 inside a generic phone T1 candidate),
//     the inner span is retained and the outer span is suppressed.
//   - If both have equal Tier, the longer span wins by rule 2b.
//
// Output:
// The resulting slice is guaranteed to be non-overlapping and sorted by Start ascending,
// then End ascending.
func Aggregate(candidates []detector.Finding, detectorPriorities map[string]int) []detector.Finding {
	if len(candidates) == 0 {
		return nil
	}

	// Step 1: Merge exact duplicates (same Start, End, Category)
	merged := mergeExactDuplicates(candidates, detectorPriorities)
	if len(merged) <= 1 {
		return merged
	}

	// Step 2: Sort all unique candidates by preference order descending
	sort.Slice(merged, func(i, j int) bool {
		return prefers(merged[i], merged[j], detectorPriorities)
	})

	// Step 3: Greedily select findings in preference order, rejecting any that overlap
	// with an already-selected finding
	var selected []detector.Finding

	for _, cand := range merged {
		hasOverlap := false
		for _, s := range selected {
			if overlaps(cand, s) {
				hasOverlap = true
				break
			}
		}
		if !hasOverlap {
			selected = append(selected, cand)
		}
	}

	// Step 4: Final sort by Start ascending, then End ascending
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Start != selected[j].Start {
			return selected[i].Start < selected[j].Start
		}
		return selected[i].End < selected[j].End
	})

	return selected
}

// duplicateKey identifies an exact duplicate finding.
type duplicateKey struct {
	Start    int
	End      int
	Category string
}

func mergeExactDuplicates(findings []detector.Finding, priorities map[string]int) []detector.Finding {
	groups := make(map[duplicateKey][]detector.Finding)
	var keys []duplicateKey

	for _, f := range findings {
		key := duplicateKey{Start: f.Start, End: f.End, Category: f.Category}
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], f)
	}

	// Sort keys deterministically by Start, then End, then Category
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Start != keys[j].Start {
			return keys[i].Start < keys[j].Start
		}
		if keys[i].End != keys[j].End {
			return keys[i].End < keys[j].End
		}
		return keys[i].Category < keys[j].Category
	})

	merged := make([]detector.Finding, 0, len(keys))
	for _, k := range keys {
		list := groups[k]
		best := list[0]

		for _, item := range list[1:] {
			// Keep highest confidence
			if item.Confidence > best.Confidence {
				best.Confidence = item.Confidence
			}
			// Keep highest tier
			if item.Tier > best.Tier {
				best.Tier = item.Tier
			}
			// Combine validated flag
			if item.Validated {
				best.Validated = true
			}
			// Keep preferred source
			prioItem := priorities[item.Source]
			prioBest := priorities[best.Source]
			if prioItem > prioBest || (prioItem == prioBest && item.Source < best.Source) {
				best.Source = item.Source
			}
		}
		merged = append(merged, best)
	}

	return merged
}

// overlaps reports whether two half-open byte spans [Start, End) overlap.
// Adjacent spans (e.g. [0, 5) and [5, 10)) do NOT overlap.
func overlaps(a, b detector.Finding) bool {
	return a.Start < b.End && b.Start < a.End
}

// prefers returns true if finding a has higher preference than finding b.
func prefers(a, b detector.Finding, priorities map[string]int) bool {
	// 1. Higher Tier wins
	if a.Tier != b.Tier {
		return a.Tier > b.Tier
	}

	// 2. Longer span wins
	spanLenA := a.End - a.Start
	spanLenB := b.End - b.Start
	if spanLenA != spanLenB {
		return spanLenA > spanLenB
	}

	// 3. Higher detector priority wins
	prioA := priorities[a.Source]
	prioB := priorities[b.Source]
	if prioA != prioB {
		return prioA > prioB
	}

	// 4. Lexicographically smaller Category wins
	if a.Category != b.Category {
		return a.Category < b.Category
	}

	// 5. Lexicographically smaller Source name wins
	return a.Source < b.Source
}
