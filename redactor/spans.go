package redactor

import (
	"fmt"
	"unicode/utf8"

	"github.com/Abhinav-DROID-NG/PrivyAI/detector"
)

// ValidateSpans checks that all finding spans are valid byte ranges within text,
// aligned to UTF-8 rune boundaries, strictly sorted by Start ascending, and non-overlapping.
func ValidateSpans(text string, findings []detector.Finding) error {
	textLen := len(text)
	prevEnd := -1

	for _, f := range findings {
		// 1. Boundary check: 0 <= Start < End <= len(text)
		if f.Start < 0 {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: "start offset is negative",
			}
		}
		if f.End <= f.Start {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: fmt.Sprintf("start offset (%d) must be strictly less than end offset (%d)", f.Start, f.End),
			}
		}
		if f.End > textLen {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: fmt.Sprintf("end offset (%d) exceeds text length (%d)", f.End, textLen),
			}
		}

		// 2. UTF-8 rune boundary check
		if !utf8.RuneStart(text[f.Start]) {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: fmt.Sprintf("start offset (%d) is not on a UTF-8 rune boundary", f.Start),
			}
		}
		if f.End < textLen && !utf8.RuneStart(text[f.End]) {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: fmt.Sprintf("end offset (%d) is not on a UTF-8 rune boundary", f.End),
			}
		}

		// 3. Sorting & Overlap check: must be strictly after previous end
		if f.Start < prevEnd {
			return &detector.SpanError{
				Start:  f.Start,
				End:    f.End,
				Length: textLen,
				Reason: fmt.Sprintf("span [%d, %d) overlaps with preceding span ending at %d", f.Start, f.End, prevEnd),
			}
		}

		prevEnd = f.End
	}

	return nil
}
