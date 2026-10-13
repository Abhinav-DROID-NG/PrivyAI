package detector

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages detectors in a deterministic, sorted order.
type Registry struct {
	mu        sync.RWMutex
	detectors map[string]Detector
	ordered   []Detector
	dirty     bool
}

// NewRegistry creates a new empty detector registry.
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
		dirty:     false,
	}
}

// Register registers a detector. It returns an error if detector is nil or already registered.
func (r *Registry) Register(d Detector) error {
	if d == nil {
		return fmt.Errorf("%w: cannot register nil detector", ErrRegistry)
	}

	name := d.Name()
	if name == "" {
		return fmt.Errorf("%w: detector name cannot be empty", ErrRegistry)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.detectors[name]; exists {
		return fmt.Errorf("%w: detector %q already registered", ErrRegistry, name)
	}

	r.detectors[name] = d
	r.dirty = true
	return nil
}

// Detectors returns a snapshot of registered detectors sorted by Priority descending, then Name ascending.
func (r *Registry) Detectors() []Detector {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.dirty && r.ordered != nil {
		result := make([]Detector, len(r.ordered))
		copy(result, r.ordered)
		return result
	}

	ordered := make([]Detector, 0, len(r.detectors))
	for _, d := range r.detectors {
		ordered = append(ordered, d)
	}

	sort.Slice(ordered, func(i, j int) bool {
		pi, pj := ordered[i].Priority(), ordered[j].Priority()
		if pi != pj {
			return pi > pj // Higher priority first
		}
		return ordered[i].Name() < ordered[j].Name() // Alphabetical ascending tie-breaker
	})

	r.ordered = ordered
	r.dirty = false

	result := make([]Detector, len(ordered))
	copy(result, ordered)
	return result
}

// Priorities returns a map of detector names to their configured priority values.
func (r *Registry) Priorities() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	priorities := make(map[string]int, len(r.detectors))
	for name, d := range r.detectors {
		priorities[name] = d.Priority()
	}
	return priorities
}

// RunSafe runs a single detector wrapped in panic recovery.
// Any panic is caught and transformed into a DetectorPanicError, ensuring fail-closed safety.
func RunSafe(d Detector, text string) (findings []Finding, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = &DetectorPanicError{
				DetectorName: d.Name(),
				Reason:       fmt.Sprintf("%v", rec),
			}
			findings = nil
		}
	}()

	return d.Detect(text), nil
}

// RunAll runs all registered detectors in deterministic priority order.
// If any detector encounters an unrecoverable panic, it immediately stops and returns a typed error.
func (r *Registry) RunAll(text string) ([]Finding, error) {
	detectors := r.Detectors()
	var allFindings []Finding

	for _, d := range detectors {
		findings, err := RunSafe(d, text)
		if err != nil {
			return nil, err
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}
