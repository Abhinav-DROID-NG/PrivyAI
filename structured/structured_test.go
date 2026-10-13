package structured

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YOURUSER/privyai/detector"
)

func TestJSONSensitiveKeys(t *testing.T) {
	tests := []struct {
		name, input, category string
	}{
		{"password", `{"password":"hunter2"}`, "secret"},
		{"passwd", `{"passwd":"hunter2"}`, "secret"},
		{"pwd", `{"pwd":"hunter2"}`, "secret"},
		{"secret", `{"secret":"value"}`, "secret"},
		{"token", `{"token":"value"}`, "token"},
		{"api key", `{"api_key":"value"}`, "api_key"},
		{"camel api key", `{"apiKey":"value"}`, "api_key"},
		{"access token", `{"accessToken":"value"}`, "token"},
		{"client secret", `{"clientSecret":"value"}`, "secret"},
		{"private key", `{"private-key":"value"}`, "private_key"},
		{"ssn", `{"ssn":"123-45-6789"}`, "ssn"},
		{"card", `{"card_number":"4111111111111111"}`, "payment_card"},
		{"authorization", `{"Authorization":"Bearer value"}`, "token"},
		{"nested", `{"outer":{"password":"value"}}`, "secret"},
		{"array object", `{"items":[{"token":"value"}]}`, "token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, fallback, err := Scan(test.input, JSON, 100)
			if err != nil || fallback {
				t.Fatalf("scan failed: %v fallback=%t", err, fallback)
			}
			if len(findings) != 1 || findings[0].Category != test.category {
				t.Fatalf("findings = %#v", findings)
			}
			if got := test.input[findings[0].Start:findings[0].End]; got != "hunter2" && got != "value" && got != "123-45-6789" && got != "4111111111111111" && got != "Bearer value" {
				t.Fatalf("unexpected span %q", got)
			}
		})
	}
}

func TestJSONFormattingAndFallback(t *testing.T) {
	input := "{\n  \"password\": \"a\\\\\\\"b\",\n  \"ok\": true\n}"
	findings, fallback, err := Scan(input, JSON, 100)
	if err != nil || fallback || len(findings) != 1 {
		t.Fatalf("scan = %#v fallback=%t err=%v", findings, fallback, err)
	}
	output := input[:findings[0].Start] + "[SECRET_REDACTED]" + input[findings[0].End:]
	if !json.Valid([]byte(output)) {
		t.Fatalf("redacted JSON is invalid: %s", output)
	}
	for _, invalid := range []string{`{"password":`, `{"password":"unterminated}`, `{"password":"x"} garbage`} {
		_, fallback, err := Scan(invalid, JSON, 100)
		if err != nil || !fallback {
			t.Fatalf("invalid JSON result fallback=%t err=%v", fallback, err)
		}
	}
}

func TestJSONDepthLimit(t *testing.T) {
	input := strings.Repeat("[", 4) + `{"password":"x"}` + strings.Repeat("]", 4)
	_, fallback, err := Scan(input, JSON, 2)
	if err != nil || !fallback {
		t.Fatalf("depth result fallback=%t err=%v", fallback, err)
	}
}

func TestJSONRejectsGoOnlyEscapes(t *testing.T) {
	_, fallback, err := Scan(`{"pAsswd":"\x8b"}`, JSON, 100)
	if err != nil || !fallback {
		t.Fatalf("fallback=%t err=%v", fallback, err)
	}
}

func TestLineFormats(t *testing.T) {
	tests := []struct {
		name, input string
		format      Format
		category    string
	}{
		{"env export", "export PASSWORD='hunter2'\n", Env, "secret"},
		{"env equals", "TOKEN=a=b=c\n", Env, "token"},
		{"env empty", "PASSWORD=\n", Env, ""},
		{"env comment", "PASSWORD=hunter2 # comment\n", Env, "secret"},
		{"env crlf", "PASSWORD=hunter2\r\n", Env, "secret"},
		{"yaml", "password: hunter2\n", YAMLLines, "secret"},
		{"yaml quoted", `token: "value"` + "\n", YAMLLines, "token"},
		{"yaml comment", "password: hunter2 # comment\n", YAMLLines, "secret"},
		{"yaml empty", "password:\n", YAMLLines, ""},
		{"yaml unrelated", "password_field: safe\n", YAMLLines, ""},
		{"env case", "aPiKeY=value\n", Env, "api_key"},
		{"env private", "PRIVATE-KEY=value\n", Env, "private_key"},
		{"env ssn", "SSN=123-45-6789\n", Env, "ssn"},
		{"env card", "CARD_NUMBER=4111111111111111\n", Env, "payment_card"},
		{"yaml auth", "authorization: Bearer value\n", YAMLLines, "token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, fallback, err := Scan(test.input, test.format, 100)
			if err != nil || fallback {
				t.Fatalf("scan failed: %v fallback=%t", err, fallback)
			}
			if test.category == "" {
				if len(findings) != 0 {
					t.Fatalf("findings = %#v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Category != test.category {
				t.Fatalf("findings = %#v", findings)
			}
			if findings[0].Source != "structured.lines" {
				t.Fatalf("source = %q", findings[0].Source)
			}
		})
	}
}

func TestFindingsMetadataOnly(t *testing.T) {
	findings, _, err := Scan(`{"password":"canary"}`, JSON, 100)
	if err != nil || len(findings) != 1 {
		t.Fatal(err)
	}
	if findings[0].Action != detector.ActionAllow || findings[0].Start == 0 {
		t.Fatalf("finding = %#v", findings[0])
	}
}
