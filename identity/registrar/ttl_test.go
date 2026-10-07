package main

import "testing"

func TestTTLBounds(t *testing.T) {
	if _, err := parseTTL("JOIN_TOKEN_TTL", "600"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "59", "86401", "10m", "300.5"} {
		if _, err := parseTTL("JWT_SVID_TTL", raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
