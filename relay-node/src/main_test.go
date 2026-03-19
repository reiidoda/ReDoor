package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/network"
	"testing"
	"time"
)

func TestRegisterAdminRoutes_DisabledWithoutToken(t *testing.T) {
	mux := http.NewServeMux()
	registerAdminRoutes(mux, network.NewKeyStore(nil), network.NewCredentialStore(time.Hour), "", time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/admin/hmac", bytes.NewBufferString("x"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when admin route disabled, got %d", rr.Code)
	}
}

func TestRegisterAdminRoutes_RejectsMissingOrInvalidToken(t *testing.T) {
	mux := http.NewServeMux()
	registerAdminRoutes(mux, network.NewKeyStore(nil), network.NewCredentialStore(time.Hour), "admin-secret", time.Minute)

	reqMissing := httptest.NewRequest(http.MethodPost, "/admin/hmac", bytes.NewBufferString("x"))
	respMissing := httptest.NewRecorder()
	mux.ServeHTTP(respMissing, reqMissing)
	if respMissing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", respMissing.Code)
	}

	reqBad := httptest.NewRequest(http.MethodPost, "/admin/hmac", bytes.NewBufferString("x"))
	reqBad.Header.Set("X-Admin-Token", "wrong")
	respBad := httptest.NewRecorder()
	mux.ServeHTTP(respBad, reqBad)
	if respBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", respBad.Code)
	}
}

func TestRegisterAdminRoutes_AcceptsValidTokenAndRotatesKey(t *testing.T) {
	ks := network.NewKeyStore([]byte("old-key"))
	mux := http.NewServeMux()
	registerAdminRoutes(mux, ks, network.NewCredentialStore(time.Hour), "admin-secret", time.Minute)

	newKey := []byte("new-key")
	req := httptest.NewRequest(
		http.MethodPost,
		"/admin/hmac",
		bytes.NewBufferString(base64.StdEncoding.EncodeToString(newKey)),
	)
	req.Header.Set("X-Admin-Token", "admin-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Equal(ks.Get(), newKey) {
		t.Fatalf("expected key rotation to update keystore")
	}
}

func TestRegisterAdminRoutes_ScopedCredentialRevocation(t *testing.T) {
	creds := network.NewCredentialStore(time.Hour)
	cred, err := creds.Issue()
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}

	mux := http.NewServeMux()
	registerAdminRoutes(mux, network.NewKeyStore(nil), creds, "admin-secret", time.Minute)

	body, _ := json.Marshal(map[string]string{"client_id": cred.ClientID})
	req := httptest.NewRequest(http.MethodPost, "/admin/scoped/revoke", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "admin-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, ok := creds.Get(cred.ClientID); ok {
		t.Fatalf("expected revoked credential to be invalid")
	}
}
