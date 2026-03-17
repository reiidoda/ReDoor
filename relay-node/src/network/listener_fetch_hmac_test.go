package network

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/storage"
	"strconv"
	"testing"
	"time"
)

// Fetch should succeed when request HMAC is correct and return response HMAC.
func TestHandleFetch_RequestAndResponseHMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("id-hmac", "user", []byte("data"))

	req := httptest.NewRequest(http.MethodGet, "/fetch?id=id-hmac", nil)
	setRequestAuthHeaders(req, key, "id-hmac", "", []byte{})
	rr := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("X-HMAC") == "" {
		t.Fatalf("expected response HMAC header")
	}
}

// Fetch should reject when request HMAC is wrong.
func TestHandleFetch_BadRequestHMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("id-hmac2", "user", []byte("data"))

	req := httptest.NewRequest(http.MethodGet, "/fetch?id=id-hmac2", bytes.NewBuffer(nil))
	req.Header.Set("X-HMAC-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-HMAC-Nonce", nextTestNonce())
	req.Header.Set("X-HMAC", "badhmac")
	rr := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad request HMAC, got %d", rr.Code)
	}
}
