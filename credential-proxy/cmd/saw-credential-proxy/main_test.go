package main

import "testing"

func TestHealthCannotBindOutsidePodLoopback(t *testing.T) {
	for _, addr := range []string{":8081", "0.0.0.0:8081", "10.0.0.1:8081", "localhost:8081", "127.0.0.1:0"} {
		t.Setenv("SAW_HEALTH_ADDR", addr)
		if _, err := healthAddress(); err == nil {
			t.Fatal("non-loopback health listener accepted")
		}
	}
	for _, addr := range []string{"127.0.0.1:8081", "[::1]:18081"} {
		t.Setenv("SAW_HEALTH_ADDR", addr)
		if _, err := healthAddress(); err != nil {
			t.Fatal("loopback health listener refused")
		}
	}
}
