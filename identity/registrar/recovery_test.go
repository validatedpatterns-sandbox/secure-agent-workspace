package main

import (
	"errors"
	"strings"
	"testing"
)

func TestHealthyEnrollmentClearsRetryBudget(t *testing.T) {
	clear, reenroll, err := nextRecovery(true, false, "present", "4", "4", "3", nil)
	if err != nil || !clear || reenroll {
		t.Fatalf("clear=%v reenroll=%v err=%v", clear, reenroll, err)
	}
}

func TestProbeFailureIsNotCredentialLoss(t *testing.T) {
	clear, reenroll, err := nextRecovery(true, false, "", "", "4", "3", errors.New("guest diagnostic unavailable: Forbidden"))
	if clear || reenroll || err == nil || !strings.Contains(err.Error(), "guest identity probe failed") || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("clear=%v reenroll=%v err=%v", clear, reenroll, err)
	}
}

func TestMissingCredentialsReenrollWhenProbeSucceeds(t *testing.T) {
	clear, reenroll, err := nextRecovery(true, false, "missing", "4", "4", "1", nil)
	if err != nil || clear || !reenroll {
		t.Fatalf("clear=%v reenroll=%v err=%v", clear, reenroll, err)
	}
}

func TestExpiredServerRecordCanReenrollDespiteProbeFailure(t *testing.T) {
	clear, reenroll, err := nextRecovery(false, true, "", "", "4", "1", errors.New("guest diagnostics unavailable"))
	if err != nil || clear || !reenroll {
		t.Fatalf("clear=%v reenroll=%v err=%v", clear, reenroll, err)
	}
}
