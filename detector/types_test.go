package detector

import (
	"encoding/json"
	"testing"
)

func TestDetectorTypes(t *testing.T) {
	// Test Tier
	for _, tier := range []Tier{TierT0Public, TierT1Personal, TierT2Confidential, TierT3Restricted, TierT4Critical} {
		str := tier.String()
		parsed, err := ParseTier(str)
		if err != nil {
			t.Fatalf("ParseTier(%q) failed: %v", str, err)
		}
		if parsed != tier {
			t.Fatalf("expected %v, got %v", tier, parsed)
		}

		txt, _ := tier.MarshalText()
		var unmarshaled Tier
		if err := unmarshaled.UnmarshalText(txt); err != nil {
			t.Fatalf("UnmarshalText failed: %v", err)
		}
		if unmarshaled != tier {
			t.Fatalf("expected %v, got %v", tier, unmarshaled)
		}

		jsn, err := json.Marshal(tier)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var jsonTier Tier
		if err := json.Unmarshal(jsn, &jsonTier); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if jsonTier != tier {
			t.Fatalf("expected %v, got %v", tier, jsonTier)
		}
	}

	// Out of bounds and errors
	if (Tier(99)).String() != "Tier(99)" {
		t.Error("unexpected Tier string")
	}
	if _, err := ParseTier("invalid"); err == nil {
		t.Error("expected ParseTier error")
	}
	var badTier Tier
	if err := badTier.UnmarshalJSON([]byte(`"bad"`)); err == nil {
		t.Error("expected error unmarshaling bad string tier")
	}
	if err := badTier.UnmarshalJSON([]byte(`[1,2,3]`)); err == nil {
		t.Error("expected error unmarshaling array tier")
	}
	if err := badTier.UnmarshalJSON([]byte(`99`)); err == nil {
		t.Error("expected error unmarshaling invalid int tier")
	}

	// Test Action
	for _, act := range []Action{ActionAllow, ActionRedact, ActionRestrict, ActionBlock} {
		str := act.String()
		parsed, err := ParseAction(str)
		if err != nil {
			t.Fatalf("ParseAction(%q) failed: %v", str, err)
		}
		if parsed != act {
			t.Fatalf("expected %v, got %v", act, parsed)
		}

		txt, _ := act.MarshalText()
		var unmarshaled Action
		if err := unmarshaled.UnmarshalText(txt); err != nil {
			t.Fatalf("UnmarshalText failed: %v", err)
		}
		if unmarshaled != act {
			t.Fatalf("expected %v, got %v", act, unmarshaled)
		}

		jsn, _ := act.MarshalJSON()
		var jsonAct Action
		if err := jsonAct.UnmarshalJSON(jsn); err != nil {
			t.Fatalf("UnmarshalJSON failed: %v", err)
		}
		if jsonAct != act {
			t.Fatalf("expected %v, got %v", act, jsonAct)
		}
	}

	if (Action(99)).String() != "Action(99)" {
		t.Error("unexpected Action string")
	}
	if _, err := ParseAction("invalid"); err == nil {
		t.Error("expected ParseAction error")
	}
	var badAct Action
	if err := badAct.UnmarshalJSON([]byte(`"invalid"`)); err == nil {
		t.Error("expected error unmarshaling invalid action string")
	}
	if err := badAct.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Error("expected error unmarshaling non-string action")
	}

	if !ActionBlock.MoreSevereThan(ActionAllow) {
		t.Error("BLOCK should be more severe than ALLOW")
	}
	if MaxAction(ActionAllow, ActionBlock) != ActionBlock {
		t.Error("MaxAction(ALLOW, BLOCK) should be BLOCK")
	}

	// Test Confidence
	for _, conf := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
		str := conf.String()
		parsed, err := ParseConfidence(str)
		if err != nil {
			t.Fatalf("ParseConfidence(%q) failed: %v", str, err)
		}
		if parsed != conf {
			t.Fatalf("expected %v, got %v", conf, parsed)
		}

		txt, _ := conf.MarshalText()
		var unmarshaled Confidence
		if err := unmarshaled.UnmarshalText(txt); err != nil {
			t.Fatalf("UnmarshalText failed: %v", err)
		}
		if unmarshaled != conf {
			t.Fatalf("expected %v, got %v", conf, unmarshaled)
		}

		jsn, _ := conf.MarshalJSON()
		var jsonConf Confidence
		if err := jsonConf.UnmarshalJSON(jsn); err != nil {
			t.Fatalf("UnmarshalJSON failed: %v", err)
		}
		if jsonConf != conf {
			t.Fatalf("expected %v, got %v", conf, jsonConf)
		}
	}

	if (Confidence(99)).String() != "Confidence(99)" {
		t.Error("unexpected Confidence string")
	}
	if _, err := ParseConfidence("invalid"); err == nil {
		t.Error("expected ParseConfidence error")
	}
	var badConf Confidence
	if err := badConf.UnmarshalJSON([]byte(`"invalid"`)); err == nil {
		t.Error("expected error unmarshaling invalid confidence string")
	}
	if err := badConf.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Error("expected error unmarshaling non-string confidence")
	}

	// Test Finding
	f := Finding{
		Category:   "email",
		Start:      0,
		End:        15,
		Tier:       TierT1Personal,
		Source:     "email",
		Action:     ActionRedact,
		Confidence: ConfidenceHigh,
		Validated:  true,
	}
	if f.String() == "" {
		t.Error("finding string should not be empty")
	}

	// DetectorPanicError.Error()
	dpe := &DetectorPanicError{DetectorName: "test", Reason: "panic msg"}
	if dpe.Error() == "" {
		t.Error("panic error should not be empty")
	}
}
