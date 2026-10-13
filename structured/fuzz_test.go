package structured

import (
	"testing"
	"unicode/utf8"
)

func FuzzScanJSON(f *testing.F) {
	f.Add(`{"password":"hunter2"}`)
	f.Add(`{"token":"value","nested":{"secret":"x"}}`)
	f.Add(`{"message":"alice@example.com"}`)
	f.Add(`{"escaped":"a\\\"b"}`)
	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			return
		}
		findings, fallback, err := Scan(input, JSON, 100)
		if err != nil {
			t.Fatal(err)
		}
		if fallback {
			return
		}
		for _, finding := range findings {
			if finding.Start < 0 || finding.Start >= finding.End || finding.End > len(input) {
				t.Fatalf("invalid span [%d,%d) for %d bytes", finding.Start, finding.End, len(input))
			}
			if !utf8.RuneStart(input[finding.Start]) || finding.End < len(input) && !utf8.RuneStart(input[finding.End]) {
				t.Fatalf("span is not rune-aligned: [%d,%d)", finding.Start, finding.End)
			}
		}
	})
}

func FuzzScanLines(f *testing.F) {
	f.Add("PASSWORD=hunter2\n")
	f.Add("export token='value'\r\n")
	f.Add("password: value\n")
	f.Fuzz(func(t *testing.T, input string) {
		for _, format := range []Format{Env, YAMLLines} {
			findings, fallback, err := Scan(input, format, 100)
			if err != nil || fallback {
				t.Fatalf("format=%s err=%v fallback=%t", format, err, fallback)
			}
			for _, finding := range findings {
				if finding.Start < 0 || finding.Start >= finding.End || finding.End > len(input) {
					t.Fatalf("invalid span [%d,%d)", finding.Start, finding.End)
				}
			}
		}
	})
}
