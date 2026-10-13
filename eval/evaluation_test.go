package eval

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	privyai "github.com/Abhinav-DROID-NG/PrivyAI"
)

var reportPath = flag.String("eval-report", "", "write JSON evaluation report to this path")

type corpusSample struct {
	name     string
	input    string
	expected []expectedFinding
}

type expectedFinding struct {
	Category string `json:"category"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type sidecar struct {
	Findings []expectedFinding `json:"findings"`
}

type metric struct {
	TP, FP, FN int
	Precision  float64 `json:"precision"`
	Recall     float64 `json:"recall"`
	F1         float64 `json:"f1"`
}

func TestEvaluation(t *testing.T) {
	engine, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	metrics := make(map[string]*metric)
	for _, sample := range loadCorpus(t) {
		result, err := engine.Process(sample.input)
		if err != nil {
			t.Fatal(err)
		}

		expected := make(map[string]expectedFinding, len(sample.expected))
		for _, finding := range sample.expected {
			expected[findingKey(finding.Category, finding.Start, finding.End)] = finding
			if metrics[finding.Category] == nil {
				metrics[finding.Category] = &metric{}
			}
		}

		actual := make(map[string]struct{}, len(result.Findings))
		for _, finding := range result.Findings {
			key := findingKey(finding.Category, finding.Start, finding.End)
			actual[key] = struct{}{}
			m := metrics[finding.Category]
			if m == nil {
				m = &metric{}
				metrics[finding.Category] = m
			}
			if _, ok := expected[key]; ok {
				m.TP++
			} else {
				m.FP++
				t.Errorf("%s: unexpected %s finding at [%d,%d)", sample.name, finding.Category, finding.Start, finding.End)
			}
		}
		for key, finding := range expected {
			if _, ok := actual[key]; !ok {
				metrics[finding.Category].FN++
				t.Errorf("%s: missing %s finding at [%d,%d)", sample.name, finding.Category, finding.Start, finding.End)
			}
		}
	}

	keys := make([]string, 0, len(metrics))
	for key := range metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		m := metrics[key]
		m.Precision = ratio(float64(m.TP), float64(m.TP+m.FP))
		m.Recall = ratio(float64(m.TP), float64(m.TP+m.FN))
		m.F1 = ratio(2*m.Precision*m.Recall, m.Precision+m.Recall)
		t.Logf("%s TP=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f", key, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
	}
	if *reportPath != "" {
		data, err := json.MarshalIndent(metrics, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*reportPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func loadCorpus(t *testing.T) []corpusSample {
	t.Helper()
	var samples []corpusSample
	for _, directory := range []string{"positive", "negative"} {
		files, err := filepath.Glob(filepath.Join("..", "testdata", directory, "*.txt"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(files)
		for _, inputPath := range files {
			input, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			sidecarPath := strings.TrimSuffix(inputPath, filepath.Ext(inputPath)) + ".json"
			data, err := os.ReadFile(sidecarPath)
			if err != nil {
				t.Fatalf("%s: read sidecar: %v", inputPath, err)
			}
			var metadata sidecar
			if err := json.Unmarshal(data, &metadata); err != nil {
				t.Fatalf("%s: decode sidecar: %v", sidecarPath, err)
			}
			samples = append(samples, corpusSample{
				name:     filepath.Join(directory, filepath.Base(inputPath)),
				input:    string(input),
				expected: metadata.Findings,
			})
		}
	}
	if len(samples) == 0 {
		t.Fatal("evaluation corpus is empty")
	}
	return samples
}

func findingKey(category string, start, end int) string {
	return fmt.Sprintf("%s:%d:%d", category, start, end)
}

func ratio(n, d float64) float64 {
	if d == 0 {
		return 1
	}
	return n / d
}

func Example() {
	fmt.Println("run: go test -v ./eval -run TestEvaluation")
	// Output: run: go test -v ./eval -run TestEvaluation
}
