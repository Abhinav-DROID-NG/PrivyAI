package detector

import (
	"errors"
	"sync"
	"testing"
)

type mockDetector struct {
	name     string
	priority int
	findings []Finding
	panics   bool
}

func (m *mockDetector) Name() string {
	return m.name
}

func (m *mockDetector) Priority() int {
	return m.priority
}

func (m *mockDetector) Detect(text string) []Finding {
	if m.panics {
		panic("detector encountered critical unexpected state")
	}
	return m.findings
}

func TestRegistryRegistration(t *testing.T) {
	reg := NewRegistry()

	// Nil detector
	if err := reg.Register(nil); err == nil {
		t.Error("expected error registering nil detector, got nil")
	}

	// Empty name
	if err := reg.Register(&mockDetector{name: ""}); err == nil {
		t.Error("expected error registering detector with empty name, got nil")
	}

	// Successful registration
	d1 := &mockDetector{name: "email", priority: 50}
	if err := reg.Register(d1); err != nil {
		t.Fatalf("unexpected error registering detector: %v", err)
	}

	// Duplicate registration
	if err := reg.Register(d1); err == nil {
		t.Error("expected error registering duplicate detector, got nil")
	}
}

func TestRegistryDeterministicSorting(t *testing.T) {
	reg := NewRegistry()

	// Register in random/non-sorted order
	detectors := []*mockDetector{
		{name: "zebra", priority: 10},
		{name: "alpha", priority: 50},
		{name: "phone", priority: 100},
		{name: "beta", priority: 50},
		{name: "email", priority: 100},
		{name: "apple", priority: 10},
	}

	for _, d := range detectors {
		if err := reg.Register(d); err != nil {
			t.Fatalf("failed to register detector %s: %v", d.name, err)
		}
	}

	sorted := reg.Detectors()
	if len(sorted) != len(detectors) {
		t.Fatalf("expected %d detectors, got %d", len(detectors), len(sorted))
	}

	// Expected order:
	// Priority 100: "email", "phone"
	// Priority 50:  "alpha", "beta"
	// Priority 10:  "apple", "zebra"
	expectedNames := []string{"email", "phone", "alpha", "beta", "apple", "zebra"}
	for i, expected := range expectedNames {
		if sorted[i].Name() != expected {
			t.Errorf("at index %d: expected detector %q, got %q", i, expected, sorted[i].Name())
		}
	}
}

func TestRegistryPanicRecovery(t *testing.T) {
	reg := NewRegistry()

	normalDetector := &mockDetector{
		name:     "normal",
		priority: 100,
		findings: []Finding{
			{Category: "test", Start: 0, End: 4, Tier: TierT1Personal, Source: "normal"},
		},
	}
	panickingDetector := &mockDetector{
		name:     "exploding",
		priority: 50,
		panics:   true,
	}

	if err := reg.Register(normalDetector); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := reg.Register(panickingDetector); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Test RunSafe isolated panic recovery
	findings, err := RunSafe(panickingDetector, "some text")
	if err == nil {
		t.Fatal("expected panic to be recovered as error, got nil")
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on panic, got %d", len(findings))
	}
	if !errors.Is(err, ErrDetectorPanic) {
		t.Errorf("expected ErrDetectorPanic, got: %v", err)
	}

	var panicErr *DetectorPanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("expected *DetectorPanicError, got: %T", err)
	}
	if panicErr.DetectorName != "exploding" {
		t.Errorf("expected detector name 'exploding', got %q", panicErr.DetectorName)
	}

	// Test RunAll halts and fails closed on panic
	allFindings, runAllErr := reg.RunAll("some text")
	if runAllErr == nil {
		t.Fatal("expected RunAll to fail when detector panics")
	}
	if allFindings != nil {
		t.Errorf("expected nil findings from failed RunAll, got: %v", allFindings)
	}
	if !errors.Is(runAllErr, ErrDetectorPanic) {
		t.Errorf("expected ErrDetectorPanic, got: %v", runAllErr)
	}
}

func TestRegistryConcurrency(t *testing.T) {
	reg := NewRegistry()
	for i := 0; i < 10; i++ {
		_ = reg.Register(&mockDetector{name: string(rune('a' + i)), priority: i})
	}

	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 100; iter++ {
				dets := reg.Detectors()
				if len(dets) != 10 {
					t.Errorf("expected 10 detectors, got %d", len(dets))
				}
			}
		}()
	}
	wg.Wait()
}
