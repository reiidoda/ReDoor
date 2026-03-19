package network

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/storage"
	"strconv"
	"testing"
	"time"
)

func TestHandleAuthRegister_IssuesCredential(t *testing.T) {
	creds := NewCredentialStore(time.Hour)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", nil)

	HandleAuthRegister(creds).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp RegistrationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal registration response: %v", err)
	}
	if resp.ClientID == "" {
		t.Fatalf("expected non-empty client_id")
	}
	if resp.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("expected future expires_at, got %d", resp.ExpiresAt)
	}

	secret, err := base64.StdEncoding.DecodeString(resp.ClientSecretB64)
	if err != nil {
		t.Fatalf("decode client secret: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected 32-byte secret, got %d", len(secret))
	}
	if _, ok := creds.Get(resp.ClientID); !ok {
		t.Fatalf("issued credential not found in store")
	}
}

func TestHandleRelay_ScopedAuthAcceptsRequest(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	body := []byte("scoped-hello")
	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "scoped-msg")
	req.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", "scoped-msg", "bob", body)

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	stored, ok := store.Retrieve("scoped-msg")
	if !ok {
		t.Fatalf("expected message to be stored")
	}
	if !bytes.Equal(stored, body) {
		t.Fatalf("stored body mismatch")
	}
}

func TestHandleRelay_ScopedAuthInvalidSignatureRejected(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	body := []byte("scoped-hello")
	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "scoped-msg")
	req.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", "scoped-msg", "bob", body)
	req.Header.Set("X-Scoped-Request-Signature", "bad-signature")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleRelay_ScopedTokenSignatureForgeryRejected(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	body := []byte("scoped-hello")
	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "scoped-token-forgery")
	req.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", "scoped-token-forgery", "bob", body)
	req.Header.Set("X-Scoped-Token-Signature", "forged-token-signature")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for forged token signature, got %d", rr.Code)
	}
}

func TestHandleRelay_ScopedAuthReplayRejected(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	handler := HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := nextTestNonce()

	body1 := []byte("scoped-replay-1")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body1))
	req1.Header.Set("X-Message-ID", "scoped-replay-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeadersWithValues(
		req1,
		cred,
		http.MethodPost,
		"/relay",
		"scoped-replay-1",
		"bob",
		body1,
		ts,
		nonce,
	)

	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first scoped request to pass, got %d", rr1.Code)
	}

	body2 := []byte("scoped-replay-2")
	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body2))
	req2.Header.Set("X-Message-ID", "scoped-replay-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeadersWithValues(
		req2,
		cred,
		http.MethodPost,
		"/relay",
		"scoped-replay-2",
		"bob",
		body2,
		ts,
		nonce,
	)

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed scoped nonce to be rejected, got %d", rr2.Code)
	}
}

func TestHandleRelay_ScopedAuthExpiredCredentialRejected(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	creds.mu.Lock()
	expired := creds.data[cred.ClientID]
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	creds.data[cred.ClientID] = expired
	creds.mu.Unlock()

	body := []byte("scoped-hello")
	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "scoped-expired")
	req.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req, cred, http.MethodPost, "/relay", "scoped-expired", "bob", body)

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleRelay_RequireScopedAuthRejectsLegacyHMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	creds := NewCredentialStore(time.Hour)

	body := []byte("legacy")
	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "legacy-msg")
	req.Header.Set("X-Receiver-ID", "bob")
	setRequestAuthHeaders(req, key, "legacy-msg", "bob", body)

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleFetch_ScopedAuthOmitsLegacyResponseHMAC(t *testing.T) {
	t.Setenv("RELAY_PAD_RESP_BYTES", "0")

	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	store.Store("fetch-scoped", "bob", []byte("payload"))
	ks := NewKeyStore(key)
	creds := NewCredentialStore(time.Hour)

	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/fetch?id=fetch-scoped", nil)
	setScopedAuthHeaders(req, cred, http.MethodGet, "/fetch", "fetch-scoped", "", []byte{})

	rr := httptest.NewRecorder()
	HandleFetch(store, ks, creds, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-HMAC"); got != "" {
		t.Fatalf("expected no X-HMAC header for scoped auth response, got %q", got)
	}
}

func TestHandleAuthRefresh_IssuesReplacementCredential(t *testing.T) {
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	setScopedAuthHeaders(req, cred, http.MethodPost, "/auth/refresh", "", "", []byte{})

	rr := httptest.NewRecorder()
	HandleAuthRefresh(creds).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var refreshed RegistrationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &refreshed); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if refreshed.ClientID == cred.ClientID {
		t.Fatalf("expected refreshed credential with new client id")
	}
	if _, ok := creds.Get(cred.ClientID); ok {
		t.Fatalf("old credential should be revoked after refresh")
	}
	if _, ok := creds.Get(refreshed.ClientID); !ok {
		t.Fatalf("new credential should be valid")
	}
}

func TestHandleAuthRevoke_MakesCredentialInvalidImmediately(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	body := []byte("revokable")
	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req1.Header.Set("X-Message-ID", "revokable-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req1, cred, http.MethodPost, "/relay", "revokable-1", "bob", body)

	rr1 := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200 before revocation, got %d", rr1.Code)
	}

	revokeBody, _ := json.Marshal(map[string]string{"client_id": cred.ClientID})
	revokeReq := httptest.NewRequest(http.MethodPost, "/admin/scoped/revoke", bytes.NewReader(revokeBody))
	revokeReq.Header.Set("X-Admin-Token", "admin-secret")
	revokeResp := httptest.NewRecorder()
	HandleAuthRevoke(creds, "admin-secret").ServeHTTP(revokeResp, revokeReq)
	if revokeResp.Code != http.StatusOK {
		t.Fatalf("expected 200 revoke, got %d", revokeResp.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req2.Header.Set("X-Message-ID", "revokable-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(req2, cred, http.MethodPost, "/relay", "revokable-2", "bob", body)

	rr2 := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revocation, got %d", rr2.Code)
	}
}

func TestCredentialRotation_OverlapAllowsThenRejectsOldGeneration(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/admin/scoped/rotate", bytes.NewReader([]byte(`{"overlap_sec":60}`)))
	rotateReq.Header.Set("X-Admin-Token", "admin-secret")
	rotateResp := httptest.NewRecorder()
	HandleAuthRotate(creds, "admin-secret", time.Minute).ServeHTTP(rotateResp, rotateReq)
	if rotateResp.Code != http.StatusOK {
		t.Fatalf("expected 200 rotate, got %d", rotateResp.Code)
	}

	body := []byte("legacy-generation")
	allowed := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	allowed.Header.Set("X-Message-ID", "rotation-allowed")
	allowed.Header.Set("X-Receiver-ID", "bob")
	setScopedAuthHeaders(allowed, cred, http.MethodPost, "/relay", "rotation-allowed", "bob", body)

	allowedResp := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(allowedResp, allowed)
	if allowedResp.Code != http.StatusOK {
		t.Fatalf("expected old generation to work in overlap, got %d", allowedResp.Code)
	}

	creds.mu.Lock()
	creds.previousValidUntil = time.Now().Add(-time.Second)
	creds.mu.Unlock()

	denied := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	denied.Header.Set("X-Message-ID", "rotation-denied")
	denied.Header.Set("X-Receiver-ID", "bob")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	setScopedAuthHeadersWithValues(
		denied,
		cred,
		http.MethodPost,
		"/relay",
		"rotation-denied",
		"bob",
		body,
		ts,
		nextTestNonce(),
	)

	deniedResp := httptest.NewRecorder()
	HandleRelay(store, ks, creds, true, 100, testMaxBlobBytes, nil, true).ServeHTTP(deniedResp, denied)
	if deniedResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected old generation to fail after overlap, got %d", deniedResp.Code)
	}
}
