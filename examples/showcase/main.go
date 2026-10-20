package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	privyai "github.com/Abhinav-DROID-NG/PrivyAI"
)

func main() {
	engine := newEngine()

	run(engine, "ALLOW", "A normal message contains no sensitive data.")
	run(engine, "REDACT", strings.Join([]string{
		"Email: alice@example.com",
		"Phone: +1 415-555-0132",
		"Public IP: 8.8.8.8",
		"Internal IP: 192.168.1.1",
		"Payment card: 4111 1111 1111 1111",
		"IBAN: GB82 WEST 1234 5698 7654 32",
		"US SSN: 123-45-6789",
		"UK NINO: AB123456C",
		"AWS key: AKIAIOSFODNN7EXAMPLE",
		"GitHub token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"Slack token: " + "xox" + "b-1234567890-abcdefghijklmnopqrstuvwxyz",
		"Stripe key: " + "sk_" + "live_1234567890abcdefghijklmnopqrstuvwxyz",
		"Google key: AIzaSyFakeGoogleApiKey1234567890abcdef",
		"JWT: eyJaaaaaaaaaa.eyJbbbbbbbbbb.sigcccccccccc",
		"Password: hunter2pass",
	}, "\n"))

	run(engine, "BLOCK", "DATABASE_URL=postgres://admin:secret@db.example.test:5432/app")

	runWithOptions(engine, "JSON", `{"user":"bob","password":"hunter2pass","card_number":"4111111111111111"}`, privyai.ProcessOptions{
		ContentType:  privyai.ContentTypeJSON,
		ContextLabel: "external_transmission",
	})
	runWithOptions(engine, "ENV", "API_KEY=abc123xyz\nexport DB_PASSWORD=\"s3cr3t\"\nNAME=bob", privyai.ProcessOptions{
		ContentType:  privyai.ContentTypeEnv,
		ContextLabel: "external_transmission",
	})
	runWithOptions(engine, "YAML LINES", "password: hunter2\nname: bob", privyai.ProcessOptions{
		ContentType:  privyai.ContentTypeYAMLLines,
		ContextLabel: "external_transmission",
	})

	restrictedEngine := newRestrictedEngine()
	run(restrictedEngine, "RESTRICT", "Please review alice@example.com before sending it.")

	runReplacementExamples()
}

func newEngine() *privyai.Engine {
	cfg := privyai.DefaultConfig()
	cfg.IdentifierJurisdictions = []string{"US", "UK"}

	engine, err := privyai.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return engine
}

func newRestrictedEngine() *privyai.Engine {
	cfg := privyai.DefaultConfig()
	cfg.IdentifierJurisdictions = []string{"US", "UK"}
	cfg.PolicyJSON = []byte(`{
		"rules": [
			{"id":"email-review","category":"email","action":"RESTRICT","conditions":["manual_review","no_third_party_logging"]},
			{"id":"t1-redact","min_tier":"T1","max_tier":"T1","action":"REDACT"},
			{"id":"t2-redact","min_tier":"T2","max_tier":"T2","action":"REDACT"},
			{"id":"t3-redact","min_tier":"T3","max_tier":"T3","action":"REDACT"},
			{"id":"t4-block","min_tier":"T4","max_tier":"T4","action":"BLOCK"}
		]
	}`)

	engine, err := privyai.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return engine
}

func run(engine *privyai.Engine, label, input string) {
	result, err := engine.Process(input)
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}

	printResult(label, input, result)
}

func runWithOptions(engine *privyai.Engine, label, input string, options privyai.ProcessOptions) {
	result, err := engine.ProcessWithOptions(input, options)
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}

	printResult(label, input, result)
}

func printResult(label, input string, result privyai.Result) {
	fmt.Printf("\n== %s ==\n", label)
	fmt.Printf("Input:    %s\n", input)
	fmt.Printf("Decision: %s\n", result.Decision)
	fmt.Printf("Output:   %s\n", result.Sanitized)
	fmt.Printf("Findings: %d\n", result.Stats.TotalFindings)
	if len(result.Conditions) > 0 {
		fmt.Printf("Conditions: %s\n", strings.Join(result.Conditions, ", "))
	}
	for _, finding := range result.Findings {
		fmt.Printf("  - %s [%s, %s, validated=%t]\n",
			finding.Category, finding.Tier, finding.Action, finding.Validated)
	}
}

func runReplacementExamples() {
	fmt.Println("\n== REPLACEMENT STRATEGIES ==")

	configs := []struct {
		name string
		cfg  privyai.Config
	}{
		{
			name: "label",
			cfg:  privyai.DefaultConfig(),
		},
		{
			name: "fixed mask",
			cfg: func() privyai.Config {
				cfg := privyai.DefaultConfig()
				cfg.Replacement.DefaultStrategy = privyai.ReplacementStrategyFixedMask
				cfg.Replacement.FixedMaskText = "****"
				return cfg
			}(),
		},
		{
			name: "partial card mask",
			cfg: func() privyai.Config {
				cfg := privyai.DefaultConfig()
				cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
					"payment_card": privyai.ReplacementStrategyPartialMask,
				}
				cfg.Replacement.PartialMasks = map[string]privyai.PartialMaskConfig{
					"payment_card": {KeepChars: 4, KeepEnd: true, MaskChar: '*'},
				}
				return cfg
			}(),
		},
		{
			name: "HMAC email",
			cfg: func() privyai.Config {
				cfg := privyai.DefaultConfig()
				cfg.Replacement.CategoryStrategies = map[string]privyai.ReplacementStrategy{
					"email": privyai.ReplacementStrategyHMAC,
				}
				cfg.Replacement.HMACKey = []byte("showcase-only-key")
				return cfg
			}(),
		},
	}

	for _, example := range configs {
		engine, err := privyai.New(example.cfg)
		if err != nil {
			log.Fatal(err)
		}
		result, err := engine.Process("Email alice@example.com and card 4111 1111 1111 1111")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s\n", example.name, result.Sanitized)
	}

	if _, err := privyai.New(func() privyai.Config {
		cfg := privyai.DefaultConfig()
		cfg.Replacement.DefaultStrategy = privyai.ReplacementStrategyHMAC
		return cfg
	}()); !errors.Is(err, privyai.ErrHMACKeyRequired) {
		log.Fatalf("expected missing HMAC key error, got %v", err)
	}
	fmt.Println("missing HMAC key: rejected during engine creation")
}
