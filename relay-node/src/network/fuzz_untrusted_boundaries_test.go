package network

import (
	"net/http/httptest"
	"testing"
	"time"
)

func FuzzValidateFixedTransportCell(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Setenv("RELAY_FIXED_CELL_BYTES", "64")
		_ = validateFixedTransportCell(data)
	})
}

func FuzzAuthorizeRequestHeaders(f *testing.F) {
	f.Add("", "", "", "", "", "", "", "")
	f.Add("token", "sig", "reqsig", "1", "nonce", "client", "clientsig", "2")

	replay := newReplayProtectorFromEnv()
	ks := NewKeyStore(nil)
	creds := NewCredentialStore(time.Minute)

	f.Fuzz(func(_ *testing.T, scopedToken, scopedTokenSig, scopedReqSig, scopedTS, scopedNonce, clientID, clientSig, clientTS string) {
		req := httptest.NewRequest("POST", "/relay", nil)
		req.Header.Set("X-Scoped-Token", scopedToken)
		req.Header.Set("X-Scoped-Token-Signature", scopedTokenSig)
		req.Header.Set("X-Scoped-Request-Signature", scopedReqSig)
		req.Header.Set("X-Scoped-Timestamp", scopedTS)
		req.Header.Set("X-Scoped-Nonce", scopedNonce)
		req.Header.Set("X-Client-ID", clientID)
		req.Header.Set("X-Client-Signature", clientSig)
		req.Header.Set("X-Client-Timestamp", clientTS)
		req.Header.Set("X-Client-Nonce", "n")
		_, _ = authorizeRequest(req, ks, creds, false, replay, "POST", "/relay", "id", "receiver", []byte("payload"))
	})
}
