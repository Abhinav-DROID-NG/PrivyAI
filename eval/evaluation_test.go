package eval

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"testing"

	privyai "github.com/YOURUSER/privyai"
)

var reportPath = flag.String("eval-report", "", "write JSON evaluation report to this path")

type sample struct {
	name, input, category string
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
	samples := []sample{
		{"email", "alice@example.com", "email"},
		{"phone", "+1-800-555-0199", "phone"},
		{"ip", "8.8.8.8", "ip"},
		{"internal-ip", "192.168.1.1", "internal_ip"},
		{"secret", "API_KEY=sk_example_secret", "secret"},
		{"card", "4111-1111-1111-1111", "payment_card"},
		{"ssn", "SSN 123-45-6789", "ssn"},
		{"database", "postgres://user:pass@db.example.test/app", "database_credentials"},
	}
	metrics := make(map[string]*metric)
	for _, sample := range samples {
		result, err := engine.Process(sample.input)
		if err != nil {
			t.Fatal(err)
		}
		m := metrics[sample.category]
		if m == nil {
			m = &metric{}
			metrics[sample.category] = m
		}
		found := false
		for _, finding := range result.Findings {
			if finding.Category == sample.category {
				found = true
				break
			}
		}
		if found {
			m.TP++
		} else {
			m.FN++
			t.Errorf("%s: missing %s finding", sample.name, sample.category)
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
