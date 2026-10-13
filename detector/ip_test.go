package detector

import (
	"testing"
)

func TestIPDetectorPositive(t *testing.T) {
	positives := []struct {
		input            string
		expectedIP       string
		expectedCategory string
		expectedTier     Tier
	}{
		// Public IPv4 (Tier T1)
		{"Connect to DNS server at 8.8.8.8 today", "8.8.8.8", "ip", TierT1Personal},
		{"Cloudflare primary resolver is 1.1.1.1", "1.1.1.1", "ip", TierT1Personal},
		{"Example domain host 93.184.216.34 online", "93.184.216.34", "ip", TierT1Personal},
		{"Public gateway 198.51.100.1 configured", "198.51.100.1", "ip", TierT1Personal},
		{"Public node 203.0.113.195 ready", "203.0.113.195", "ip", TierT1Personal},

		// Internal IPv4 (Tier T2)
		{"Private subnet node 10.0.0.1 initialized", "10.0.0.1", "internal_ip", TierT2Confidential},
		{"Local router gateway 192.168.1.1 found", "192.168.1.1", "internal_ip", TierT2Confidential},
		{"Corporate private IP 172.16.254.1 is up", "172.16.254.1", "internal_ip", TierT2Confidential},
		{"Host loopback is 127.0.0.1 on machine", "127.0.0.1", "internal_ip", TierT2Confidential},
		{"Link local address 169.254.10.20 assigned", "169.254.10.20", "internal_ip", TierT2Confidential},

		// Public IPv6 (Tier T1)
		{"Google IPv6 DNS 2001:4860:4860::8888 reachable", "2001:4860:4860::8888", "ip", TierT1Personal},
		{"Cloudflare IPv6 2606:4700:4700::1111 works", "2606:4700:4700::1111", "ip", TierT1Personal},

		// Internal IPv6 (Tier T2)
		{"IPv6 loopback is ::1 localhost", "::1", "internal_ip", TierT2Confidential},
		{"Unique local IPv6 fc00::1 node", "fc00::1", "internal_ip", TierT2Confidential},
		{"Link local IPv6 fe80::1 interface", "fe80::1", "internal_ip", TierT2Confidential},
	}

	d := NewIPDetector()

	for _, tt := range positives {
		t.Run(tt.input, func(t *testing.T) {
			findings := d.Detect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected finding for input %q, got none", tt.input)
			}
			f := findings[0]
			matched := tt.input[f.Start:f.End]
			if matched != tt.expectedIP {
				t.Errorf("expected IP %q, got %q", tt.expectedIP, matched)
			}
			if f.Category != tt.expectedCategory {
				t.Errorf("expected category %q, got %q", tt.expectedCategory, f.Category)
			}
			if f.Tier != tt.expectedTier {
				t.Errorf("expected tier %v, got %v", tt.expectedTier, f.Tier)
			}
			if !f.Validated {
				t.Errorf("expected Validated=true")
			}
		})
	}
}

func TestIPDetectorNegative(t *testing.T) {
	negatives := []string{
		"Clean text with no IP addresses",
		"Semantic version 1.2.3 is released",
		"Extended version 1.2.3.4.5 should be rejected",
		"Version with prefix v1.2.3.4 should be rejected",
		"Leading zero octet 192.168.01.1 is invalid",
		"Octet starting with double zeroes 10.00.0.1 is invalid",
		"Out of range octet 256.100.1.1 is invalid",
		"Out of range octet 192.168.1.999 is invalid",
		"Incomplete IP address 192.168.1.",
		"Placeholder [IP_REDACTED] must not trigger",
		"Placeholder [INTERNAL_IP_REDACTED] must not trigger",
		"Word embedded ip192.168.1.1 rejected",
		"Word trailing 192.168.1.1abc rejected",
		"MAC address 00:1A:2B:3C:4D:5E rejected",
		"Too short colons 12:34 rejected",
	}

	d := NewIPDetector()

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			findings := d.Detect(input)
			if len(findings) > 0 {
				t.Fatalf("expected NO findings for negative input %q, got %d findings: %+v", input, len(findings), findings)
			}
		})
	}
}

func TestIPDetectorEdgeCases(t *testing.T) {
	d := NewIPDetector()

	// Empty string
	if len(d.Detect("")) != 0 {
		t.Error("expected 0 findings for empty string")
	}

	// IP at start
	inputStart := "10.0.0.1 is the gateway"
	findingsStart := d.Detect(inputStart)
	if len(findingsStart) != 1 || findingsStart[0].Start != 0 || findingsStart[0].End != 8 {
		t.Errorf("expected finding at [0, 8), got: %+v", findingsStart)
	}

	// IP at end
	inputEnd := "Connecting to 192.168.1.1"
	findingsEnd := d.Detect(inputEnd)
	if len(findingsEnd) != 1 || findingsEnd[0].End != len(inputEnd) {
		t.Errorf("expected finding at end, got: %+v", findingsEnd)
	}

	// Multiple IPs
	multiple := "Public 8.8.8.8 and private 10.0.0.1 and loopback ::1"
	findingsMultiple := d.Detect(multiple)
	if len(findingsMultiple) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findingsMultiple))
	}
	if findingsMultiple[0].Category != "ip" {
		t.Errorf("first should be public ip, got %s", findingsMultiple[0].Category)
	}
	if findingsMultiple[1].Category != "internal_ip" {
		t.Errorf("second should be internal_ip, got %s", findingsMultiple[1].Category)
	}
	if findingsMultiple[2].Category != "internal_ip" {
		t.Errorf("third should be internal_ip, got %s", findingsMultiple[2].Category)
	}
}

func FuzzIPDetector(f *testing.F) {
	f.Add("Connect to 8.8.8.8 and 10.0.0.1")
	f.Add("IPv6 ::1 localhost")
	f.Add("Google 2001:4860:4860::8888")
	f.Add("Version 1.2.3.4")
	f.Add("[IP_REDACTED]")

	d := NewIPDetector()
	f.Fuzz(func(t *testing.T, text string) {
		findings := d.Detect(text)
		for _, finding := range findings {
			if finding.Start < 0 || finding.Start >= finding.End || finding.End > len(text) {
				t.Fatalf("invalid IP span [%d, %d) for text length %d", finding.Start, finding.End, len(text))
			}
		}
	})
}
