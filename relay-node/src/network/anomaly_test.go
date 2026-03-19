package network

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/storage"
	"testing"
	"time"
)

func TestAnomalyController_ThresholdAndRateAlerts(t *testing.T) {
	ac := NewAnomalyController(
		50*time.Millisecond,
		detectorConfig{Threshold: 2, RateMultiplier: 2},
		detectorConfig{Threshold: 2, RateMultiplier: 2},
		detectorConfig{Threshold: 2, RateMultiplier: 2},
	)
	base := time.Unix(1_000, 0)

	ac.observeReplay(base)
	ac.observeReplay(base)
	first := ac.Snapshot()
	if first.ReplaySpike.Alerts == 0 {
		t.Fatalf("expected threshold alert for replay spike")
	}

	nextWindow := base.Add(60 * time.Millisecond)
	ac.observeReplay(nextWindow)
	ac.observeReplay(nextWindow)
	ac.observeReplay(nextWindow)
	second := ac.Snapshot()
	if second.ReplaySpike.Alerts < 2 {
		t.Fatalf("expected second alert after rate increase, got %+v", second.ReplaySpike)
	}
	if second.ReplaySpike.LastAlertReason == "" {
		t.Fatalf("expected alert reason to be set")
	}
}

func TestHandleAnomalyMetrics(t *testing.T) {
	ac := NewAnomalyController(
		time.Minute,
		detectorConfig{Threshold: 1, RateMultiplier: 2},
		detectorConfig{Threshold: 1, RateMultiplier: 2},
		detectorConfig{Threshold: 1, RateMultiplier: 2},
	)
	ac.observeMalformed(time.Now())

	req := httptest.NewRequest(http.MethodGet, "/metrics/anomaly", nil)
	rr := httptest.NewRecorder()
	HandleAnomalyMetrics(ac).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var snapshot AnomalySnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode anomaly snapshot: %v", err)
	}
	if snapshot.MalformedBurst.CurrentWindowCount == 0 {
		t.Fatalf("expected malformed burst count to be non-zero")
	}
	if snapshot.ActionMap["relay_malformed_burst"] == "" {
		t.Fatalf("expected action mapping for malformed burst")
	}
}

func TestRelayHandler_RecordsReplayAndCredentialSignals(t *testing.T) {
	ac := NewAnomalyController(
		time.Minute,
		detectorConfig{Threshold: 1, RateMultiplier: 2},
		detectorConfig{Threshold: 1, RateMultiplier: 2},
		detectorConfig{Threshold: 1, RateMultiplier: 2},
	)
	SetAnomalyController(ac)
	defer SetAnomalyController(nil)

	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, nil)
	body := []byte("payload")

	// First request succeeds and sets nonce in replay protector.
	msgID := "anomaly-replay-1"
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req1.Header.Set("X-Message-ID", msgID)
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req1, cred, http.MethodPost, "/relay", msgID, "bob", body)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected baseline request 200, got %d", rr1.Code)
	}

	// Replay the exact signed request to trigger replay-protector rejection.
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req2.Header.Set("X-Message-ID", msgID)
	req2.Header.Set("X-Receiver-ID", "bob")
	for _, k := range []string{"X-Scoped-Token", "X-Scoped-Token-Signature", "X-Scoped-Request-Signature", "X-Scoped-Timestamp", "X-Scoped-Nonce"} {
		req2.Header.Set(k, req1.Header.Get(k))
	}
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusOK {
		t.Fatalf("expected replay rejection, got 200")
	}

	// Invalid signature to simulate credential spray attempt.
	req3 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req3.Header.Set("X-Message-ID", "anomaly-cred-1")
	req3.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req3, cred, http.MethodPost, "/relay", "anomaly-cred-1", "bob", body)
	req3.Header.Set("X-Scoped-Request-Signature", "invalid-signature")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code == http.StatusOK {
		t.Fatalf("expected credential validation failure")
	}

	snapshot := ac.Snapshot()
	if snapshot.ReplaySpike.CurrentWindowCount == 0 {
		t.Fatalf("expected replay signal to increment")
	}
	if snapshot.CredentialSpray.CurrentWindowCount == 0 {
		t.Fatalf("expected credential spray signal to increment")
	}
}
