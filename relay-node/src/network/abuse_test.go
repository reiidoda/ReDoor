package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/storage"
	"strconv"
	"strings"
	"testing"
	"time"
)

func challengeKeyForRequest(ac *AbuseController, req *http.Request) string {
	keys := resolveAbuseKeys(req, time.Now(), ac.spendUnitWindow)
	if ac.bucketMode == bucketModeLegacyClient {
		return keys.legacy
	}
	return keys.spendUnit
}

func solveChallenge(t *testing.T, req *http.Request, clientKey, receiver string, difficulty uint) {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("X-Abuse-Challenge-Timestamp", ts)

	for i := 0; i < 2_000_000; i++ {
		solution := strconv.Itoa(i)
		canonical := strings.Join([]string{
			clientKey,
			receiver,
			strings.ToUpper(req.Method),
			req.URL.Path,
			ts,
			solution,
		}, "\n")
		sum := sha256.Sum256([]byte(canonical))
		if hasLeadingZeroBits(sum[:], difficulty) {
			req.Header.Set("X-Abuse-Challenge-Solution", solution)
			return
		}
	}

	t.Fatalf("failed to solve challenge for difficulty=%d", difficulty)
}

func TestHandleRelayWithAbuse_ClientBudgetThrottle(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           1,
		ClientBurst:         1,
		ReceiverRPS:         100,
		ReceiverBurst:       100,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	body1 := []byte("first")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body1))
	req1.Header.Set("X-Message-ID", "abuse-client-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req1, cred, http.MethodPost, "/relay", "abuse-client-1", "bob", body1)
	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, req1)
	if resp1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", resp1.Code)
	}

	body2 := []byte("second")
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body2))
	req2.Header.Set("X-Message-ID", "abuse-client-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req2, cred, http.MethodPost, "/relay", "abuse-client-2", "bob", body2)
	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, req2)
	if resp2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for client budget throttle, got %d", resp2.Code)
	}

	snapshot := abuse.Snapshot()
	if snapshot.ClientBudgetThrottle == 0 {
		t.Fatalf("expected client budget throttle metric to increment")
	}
	if snapshot.Denied == 0 {
		t.Fatalf("expected denied metric to increment")
	}
}

func TestHandleRelayWithAbuse_ReceiverBudgetThrottleAcrossClients(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	credA, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential A: %v", err)
	}
	credB, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential B: %v", err)
	}

	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           100,
		ClientBurst:         100,
		ReceiverRPS:         1,
		ReceiverBurst:       1,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	body1 := []byte("receiver-a")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body1))
	req1.Header.Set("X-Message-ID", "abuse-receiver-1")
	req1.Header.Set("X-Receiver-ID", "shared")
	setScopedAuthHeaders(req1, credA, http.MethodPost, "/relay", "abuse-receiver-1", "shared", body1)
	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, req1)
	if resp1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", resp1.Code)
	}

	body2 := []byte("receiver-b")
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body2))
	req2.Header.Set("X-Message-ID", "abuse-receiver-2")
	req2.Header.Set("X-Receiver-ID", "shared")
	setScopedAuthHeaders(req2, credB, http.MethodPost, "/relay", "abuse-receiver-2", "shared", body2)
	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, req2)
	if resp2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for receiver budget throttle, got %d", resp2.Code)
	}

	snapshot := abuse.Snapshot()
	if snapshot.ReceiverBudgetThrottle == 0 {
		t.Fatalf("expected receiver budget throttle metric to increment")
	}
}

func TestHandleRelayWithAbuse_AdaptiveChallengeMode(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	difficulty := uint(10)
	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           1,
		ClientBurst:         1,
		ReceiverRPS:         100,
		ReceiverBurst:       100,
		ChallengeDifficulty: difficulty,
		ChallengeWindow:     60 * time.Second,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	body1 := []byte("challenge-1")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body1))
	req1.Header.Set("X-Message-ID", "abuse-challenge-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req1, cred, http.MethodPost, "/relay", "abuse-challenge-1", "bob", body1)
	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, req1)
	if resp1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", resp1.Code)
	}

	body2 := []byte("challenge-2")
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body2))
	req2.Header.Set("X-Message-ID", "abuse-challenge-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req2, cred, http.MethodPost, "/relay", "abuse-challenge-2", "bob", body2)
	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, req2)
	if resp2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 challenge response, got %d", resp2.Code)
	}
	if got := resp2.Header().Get("X-Abuse-Challenge-Difficulty"); got != fmt.Sprintf("%d", difficulty) {
		t.Fatalf("unexpected challenge difficulty header: %q", got)
	}

	body3 := []byte("challenge-3")
	req3 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body3))
	req3.Header.Set("X-Message-ID", "abuse-challenge-3")
	req3.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req3, cred, http.MethodPost, "/relay", "abuse-challenge-3", "bob", body3)
	solveChallenge(t, req3, challengeKeyForRequest(abuse, req3), "bob", difficulty)

	resp3 := httptest.NewRecorder()
	handler.ServeHTTP(resp3, req3)
	if resp3.Code != http.StatusOK {
		t.Fatalf("expected challenge-solved request to pass, got %d", resp3.Code)
	}

	snapshot := abuse.Snapshot()
	if snapshot.ChallengeRequired == 0 || snapshot.ChallengeFailed == 0 || snapshot.ChallengePassed == 0 {
		t.Fatalf("expected challenge metrics to increment, got %+v", snapshot)
	}
}

func TestHandleAbuseMetrics_ReportsSnapshot(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           1,
		ClientBurst:         1,
		ReceiverRPS:         100,
		ReceiverBurst:       100,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)
	for idx := 0; idx < 2; idx++ {
		body := []byte(fmt.Sprintf("metrics-%d", idx))
		id := fmt.Sprintf("abuse-metrics-%d", idx)
		req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
		req.Header.Set("X-Message-ID", id)
		req.Header.Set("X-Receiver-ID", "bob")
		setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", id, "bob", body)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics/abuse", nil)
	metricsResp := httptest.NewRecorder()
	HandleAbuseMetrics(abuse).ServeHTTP(metricsResp, metricsReq)
	if metricsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from metrics endpoint, got %d", metricsResp.Code)
	}

	var snapshot AbuseMetricsSnapshot
	if err := json.Unmarshal(metricsResp.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode metrics json: %v", err)
	}
	if snapshot.RequestsAllowed == 0 {
		t.Fatalf("expected requests_allowed > 0, got %+v", snapshot)
	}
	if snapshot.Denied == 0 || snapshot.ClientBudgetThrottle == 0 {
		t.Fatalf("expected denied/client throttle metrics > 0, got %+v", snapshot)
	}
}

func TestHandleRelayWithAbuse_DistributedBurstKeepsQueueStable(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           1000,
		ClientBurst:         1000,
		ReceiverRPS:         5,
		ReceiverBurst:       5,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	var accepted int
	var denied int
	for i := 0; i < 25; i++ {
		cred, err := creds.Issue()
		if err != nil {
			t.Fatalf("issue credential %d: %v", i, err)
		}
		id := fmt.Sprintf("burst-%d", i)
		body := []byte(id)
		req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
		req.Header.Set("X-Message-ID", id)
		req.Header.Set("X-Receiver-ID", "hotspot")
		setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", id, "hotspot", body)

		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		switch resp.Code {
		case http.StatusOK:
			accepted++
		case http.StatusTooManyRequests:
			denied++
		default:
			t.Fatalf("unexpected status %d for request %d", resp.Code, i)
		}
	}

	if denied == 0 {
		t.Fatalf("expected at least one request to be throttled in burst abuse scenario")
	}

	queued := store.Count("hotspot")
	if queued != accepted {
		t.Fatalf("queue count mismatch: queued=%d accepted=%d denied=%d", queued, accepted, denied)
	}
	if queued > 10 {
		t.Fatalf("queue should remain bounded under burst abuse, got %d", queued)
	}
}

func TestResolveAbuseKeys_AnonymousSpendUnitRotatesByWindow(t *testing.T) {
	credStore := NewCredentialStore(time.Hour)
	cred, err := credStore.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("payload")))
	req.Header.Set("X-Message-ID", "rotation-msg")
	req.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", "rotation-msg", "bob", []byte("payload"))

	window := 5 * time.Second
	now := time.Unix(1_700_000_000, 0)
	keysNow := resolveAbuseKeys(req, now, window)
	keysFuture := resolveAbuseKeys(req, now.Add(window*2), window)

	if keysNow.legacy != keysFuture.legacy {
		t.Fatalf("legacy key should remain stable, got %q and %q", keysNow.legacy, keysFuture.legacy)
	}
	if keysNow.spendUnit == keysFuture.spendUnit {
		t.Fatalf("expected spend unit key to rotate across windows")
	}
}

func TestResolveAbuseKeys_IssuerKeyUsesGeneration(t *testing.T) {
	credStore := NewCredentialStore(time.Hour)
	cred, err := credStore.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/relay", nil)
	req.Header.Set("X-Scoped-Token", cred.ScopedToken)
	req.Header.Set("X-Scoped-Token-Signature", cred.ScopedTokenSigB64)

	keys := resolveAbuseKeys(req, time.Now(), 30*time.Second)
	expected := fmt.Sprintf("issuer:generation:%d", cred.Generation)
	if keys.issuer != expected {
		t.Fatalf("expected issuer key %q, got %q", expected, keys.issuer)
	}
}

func TestHandleRelayWithAbuse_IssuerBudgetThrottleAcrossTokens(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	credA, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential A: %v", err)
	}
	credB, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential B: %v", err)
	}

	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           100,
		ClientBurst:         100,
		ReceiverRPS:         100,
		ReceiverBurst:       100,
		IssuerRPS:           1,
		IssuerBurst:         1,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	bodyA := []byte("issuer-a")
	reqA := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(bodyA))
	reqA.Header.Set("X-Message-ID", "issuer-budget-1")
	reqA.Header.Set("X-Receiver-ID", "alice")
	setScopedAuthHeaders(reqA, credA, http.MethodPost, "/relay", "issuer-budget-1", "alice", bodyA)
	respA := httptest.NewRecorder()
	handler.ServeHTTP(respA, reqA)
	if respA.Code != http.StatusOK {
		t.Fatalf("expected first issuer request to pass, got %d", respA.Code)
	}

	bodyB := []byte("issuer-b")
	reqB := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(bodyB))
	reqB.Header.Set("X-Message-ID", "issuer-budget-2")
	reqB.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(reqB, credB, http.MethodPost, "/relay", "issuer-budget-2", "bob", bodyB)
	respB := httptest.NewRecorder()
	handler.ServeHTTP(respB, reqB)
	if respB.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for issuer budget throttle, got %d", respB.Code)
	}

	snapshot := abuse.Snapshot()
	if snapshot.IssuerBudgetThrottle == 0 {
		t.Fatalf("expected issuer budget throttle metric to increment")
	}
}

func TestHandleRelayWithAbuse_LegacyRollbackModeStillSupported(t *testing.T) {
	store := storage.NewStore()
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	abuse := NewAbuseController(AbuseConfig{
		ClientRPS:           1,
		ClientBurst:         1,
		ReceiverRPS:         100,
		ReceiverBurst:       100,
		BucketMode:          bucketModeLegacyClient,
		ChallengeDifficulty: 0,
	})

	handler := HandleRelayWithAbuse(store, NewKeyStore(nil), creds, true, 100, testMaxBlobBytes, nil, true, abuse)

	body1 := []byte("legacy-1")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body1))
	req1.Header.Set("X-Message-ID", "legacy-bucket-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req1, cred, http.MethodPost, "/relay", "legacy-bucket-1", "bob", body1)
	resp1 := httptest.NewRecorder()
	handler.ServeHTTP(resp1, req1)
	if resp1.Code != http.StatusOK {
		t.Fatalf("expected first legacy-bucket request to pass, got %d", resp1.Code)
	}

	body2 := []byte("legacy-2")
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body2))
	req2.Header.Set("X-Message-ID", "legacy-bucket-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req2, cred, http.MethodPost, "/relay", "legacy-bucket-2", "bob", body2)
	resp2 := httptest.NewRecorder()
	handler.ServeHTTP(resp2, req2)
	if resp2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 in legacy rollback mode, got %d", resp2.Code)
	}
}
