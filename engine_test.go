package privyai

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestEngineNew(t *testing.T) {
	// Valid default config
	eng, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("unexpected error creating engine: %v", err)
	}
	if eng == nil {
		t.Fatal("engine should not be nil")
	}

	// Invalid config
	invalidCfg := DefaultConfig()
	invalidCfg.MaxInputBytes = -10
	_, err = New(invalidCfg)
	if err == nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got: %v", err)
	}
}

func TestEngineInputSizeLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxInputBytes = 50 // small limit for testing

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Within limit
	res, err := eng.Process("Short input text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Blocked {
		t.Error("short input should not be blocked")
	}

	// Exceeding limit
	tooLong := strings.Repeat("A", 100)
	res, err = eng.Process(tooLong)
	if err == nil || !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got: %v", err)
	}
	if !res.Blocked {
		t.Error("expected result to be blocked on size limit breach")
	}
	if res.Sanitized != "" {
		t.Errorf("expected empty sanitized string on FailClosedNoOutput, got: %q", res.Sanitized)
	}
}

func TestEngineUTF8Validation(t *testing.T) {
	eng, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invalid UTF-8 sequence: 0xff, 0xfe
	invalidUTF8 := string([]byte{0xff, 0xfe, 'h', 'e', 'l', 'l', 'o'})

	res, err := eng.Process(invalidUTF8)
	if err == nil || !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("expected ErrInvalidUTF8, got: %v", err)
	}
	if !res.Blocked {
		t.Error("expected blocked result on invalid UTF-8")
	}

	// Now allow invalid UTF-8 via config
	allowCfg := DefaultConfig()
	allowCfg.AllowInvalidUTF8 = true
	engAllow, err := New(allowCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err = engAllow.Process(invalidUTF8)
	if err != nil {
		t.Fatalf("expected no error when AllowInvalidUTF8=true, got: %v", err)
	}
	if res.Blocked {
		t.Error("expected not blocked when AllowInvalidUTF8=true")
	}
}

func TestEngineFailClosedBehavior(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxInputBytes = 10
	cfg.FailClosedBehavior = FailClosedRedactAll

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res, err := eng.Process("This input exceeds 10 bytes")
	if err == nil || !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got: %v", err)
	}
	if res.Sanitized != "[REDACTED]" {
		t.Errorf("expected [REDACTED] for FailClosedRedactAll, got: %q", res.Sanitized)
	}
}

func TestEngineProcessConcurrency(t *testing.T) {
	eng, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				res, err := eng.Process("Hello world, concurrency test text")
				if err != nil {
					t.Errorf("unexpected error in goroutine: %v", err)
				}
				if res.Sanitized != "Hello world, concurrency test text" {
					t.Errorf("unexpected sanitized output: %s", res.Sanitized)
				}
			}
		}(i)
	}
	wg.Wait()
}

type panickingDetector struct{}

func (p *panickingDetector) Name() string                 { return "panic_det" }
func (p *panickingDetector) Priority() int                { return 10 }
func (p *panickingDetector) Detect(text string) []Finding { panic("boom") }

func TestEngineDetectorPanicFailClosed(t *testing.T) {
	cfg := DefaultConfig()
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Register panicking detector
	if err := eng.registry.Register(&panickingDetector{}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	res, err := eng.Process("test text")
	if err == nil || !errors.Is(err, ErrDetectorPanic) {
		t.Fatalf("expected ErrDetectorPanic, got: %v", err)
	}
	if !res.Blocked {
		t.Error("expected blocked result on detector panic when FailClosedOnError=true")
	}

	// Now with FailClosedOnError = false
	cfgOpen := DefaultConfig()
	cfgOpen.FailClosedOnError = false
	engOpen, err := New(cfgOpen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = engOpen.registry.Register(&panickingDetector{})

	resOpen, errOpen := engOpen.Process("test text")
	if errOpen == nil || !errors.Is(errOpen, ErrDetectorPanic) {
		t.Fatalf("expected ErrDetectorPanic, got: %v", errOpen)
	}
	if resOpen.Blocked {
		t.Error("expected not blocked on FailClosedOnError=false")
	}
}
