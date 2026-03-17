package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"redoor-relay/src/onion"
	"redoor-relay/src/storage"
	"strconv"
	"testing"
	"time"
)

const testMaxBlobBytes = 1 << 20 // 1 MiB

func rotatingMailboxHandle(receiver string, epoch int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", mailboxHandleVersion, epoch, receiver)))
	return fmt.Sprintf("%s_%d_%s", mailboxHandleVersion, epoch, hex.EncodeToString(sum[:]))
}

func TestHandleRelayAndFetch_HMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	// 1) POST /relay with correct HMAC
	relayReq := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello")))
	relayReq.Header.Set("X-Message-ID", "abc123")
	relayReq.Header.Set("X-Receiver-ID", "bob")
	setRequestAuthHeaders(relayReq, key, "abc123", "bob", []byte("hello"))
	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, relayReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// 2) GET /fetch should return blob and HMAC
	fetchReq := httptest.NewRequest(http.MethodGet, "/fetch?id=abc123", nil)
	setRequestAuthHeaders(fetchReq, key, "abc123", "", []byte{})
	fr := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(fr, fetchReq)
	if fr.Code != http.StatusOK {
		t.Fatalf("expected 200 on fetch, got %d", fr.Code)
	}
	respMac := fr.Header().Get("X-HMAC")
	expected := computeHMAC(key, "abc123", "", fr.Body.Bytes())
	if respMac != expected {
		t.Fatalf("fetch HMAC mismatch")
	}
}

func TestHandleFetchPending_HMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	// preload store
	store.Store("msg1", "carol", []byte("cipher"))

	req := httptest.NewRequest(http.MethodGet, "/fetch_pending?receiver=carol", nil)
	setRequestAuthHeaders(req, key, "", "carol", []byte{})
	rr := httptest.NewRecorder()
	HandleFetchPending(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	mac := rr.Header().Get("X-HMAC")
	body := rr.Body.Bytes()
	expected := computeHMACBytes(key, body)
	if mac != expected {
		t.Fatalf("pending HMAC mismatch")
	}

	// blob should be base64 of "cipher"
	type resp struct {
		ID   string `json:"id"`
		Blob string `json:"blob_base64"`
	}
	var parsed resp
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(parsed.Blob)
	if err != nil || string(blob) != "cipher" {
		t.Fatalf("unexpected blob decode")
	}
}

func TestHandleFetchPending_MissingRequestHMACRejected(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("msg2", "dave", []byte("cipher"))

	req := httptest.NewRequest(http.MethodGet, "/fetch_pending?receiver=dave", nil)
	rr := httptest.NewRecorder()
	HandleFetchPending(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when request auth headers are missing, got %d", rr.Code)
	}
}

func TestHandleFetchPending_BadRequestHMACRejected(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("msg3", "erin", []byte("cipher"))

	req := httptest.NewRequest(http.MethodGet, "/fetch_pending?receiver=erin", nil)
	req.Header.Set("X-HMAC-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-HMAC-Nonce", nextTestNonce())
	req.Header.Set("X-HMAC", "badmac")
	rr := httptest.NewRecorder()
	HandleFetchPending(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad request HMAC, got %d", rr.Code)
	}
}

func TestHandleRelay_BadHMACRejected(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	relayReq := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello")))
	relayReq.Header.Set("X-Message-ID", "abc123")
	relayReq.Header.Set("X-Receiver-ID", "bob")
	relayReq.Header.Set("X-HMAC-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	relayReq.Header.Set("X-HMAC-Nonce", nextTestNonce())
	relayReq.Header.Set("X-HMAC", "badmac")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, relayReq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad HMAC, got %d", rr.Code)
	}
}

func TestHandleFetch_MissingHMACRejected(t *testing.T) {
	// Fetch requires request HMAC when HMAC mode is enabled.
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("id1", "user", []byte("payload"))

	req := httptest.NewRequest(http.MethodGet, "/fetch?id=id1", nil)
	rr := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when request auth headers are missing, got %d", rr.Code)
	}
}

func TestHMACRotationEndpoint(t *testing.T) {
	key1 := []byte("key-one-0000000000000000000000")
	key2 := []byte("key-two-0000000000000000000000")
	store := storage.NewStore()
	ks := NewKeyStore(key1)

	// Rotate via handler
	body := base64.StdEncoding.EncodeToString(key2)
	req := httptest.NewRequest(http.MethodPost, "/admin/hmac", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	// use empty admin token (disabled)
	adminHandler := func(w http.ResponseWriter, r *http.Request) {
		// reuse same logic as main.go admin endpoint
		// (duplicated minimal inline to avoid importing main)
		newBody, _ := io.ReadAll(r.Body)
		newKey, _ := base64.StdEncoding.DecodeString(string(newBody))
		ks.Set(newKey)
		w.WriteHeader(http.StatusOK)
	}
	adminHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotation endpoint failed: %d", rr.Code)
	}

	// Now relay should accept blobs signed with key2 but reject key1
	okTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	okNonce := nextTestNonce()
	goodMac := computeRequestHMAC(key2, "abc", "bob", []byte("hi"), okTimestamp, okNonce)

	okReq := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hi")))
	okReq.Header.Set("X-Message-ID", "abc")
	okReq.Header.Set("X-Receiver-ID", "bob")
	okReq.Header.Set("X-HMAC-Timestamp", okTimestamp)
	okReq.Header.Set("X-HMAC-Nonce", okNonce)
	okReq.Header.Set("X-HMAC", goodMac)
	okResp := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(okResp, okReq)
	if okResp.Code != http.StatusOK {
		t.Fatalf("expected accept after rotation, got %d", okResp.Code)
	}

	badTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	badNonce := nextTestNonce()
	badMac := computeRequestHMAC(key1, "abc2", "bob", []byte("hi"), badTimestamp, badNonce)

	badReq := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hi")))
	badReq.Header.Set("X-Message-ID", "abc2")
	badReq.Header.Set("X-Receiver-ID", "bob")
	badReq.Header.Set("X-HMAC-Timestamp", badTimestamp)
	badReq.Header.Set("X-HMAC-Nonce", badNonce)
	badReq.Header.Set("X-HMAC", badMac)
	badResp := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(badResp, badReq)
	if badResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old key after rotation, got %d", badResp.Code)
	}
}

func TestHandleRelay_PersistentPublicBlobCanBeFetchedMultipleTimes(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)

	body := []byte("prekey-json")
	relayReq := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	relayReq.Header.Set("X-Message-ID", "prekey-1")
	relayReq.Header.Set("X-Receiver-ID", "public")
	relayReq.Header.Set("X-Persistent", "true")

	relayResp := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(relayResp, relayReq)
	if relayResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", relayResp.Code)
	}

	for i := 0; i < 2; i++ {
		fetchReq := httptest.NewRequest(http.MethodGet, "/fetch?id=prekey-1", nil)
		fetchResp := httptest.NewRecorder()
		HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(fetchResp, fetchReq)
		if fetchResp.Code != http.StatusOK {
			t.Fatalf("fetch %d expected 200, got %d", i+1, fetchResp.Code)
		}
		if !bytes.Equal(fetchResp.Body.Bytes(), body) {
			t.Fatalf("fetch %d returned unexpected body", i+1)
		}
	}
}

func TestHandleRelay_PersistentNonPublicRejected(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("payload")))
	req.Header.Set("X-Message-ID", "msg-1")
	req.Header.Set("X-Receiver-ID", "bob")
	req.Header.Set("X-Persistent", "true")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when non-public receiver requests persistence, got %d", rr.Code)
	}
}

func TestHandleRelay_RejectsOversizedBody(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("12345")))
	req.Header.Set("X-Message-ID", "too-big")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, 4, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", rr.Code)
	}

	// Ensure rejected body is not persisted.
	fetchReq := httptest.NewRequest(http.MethodGet, "/fetch?id=too-big", nil)
	fetchResp := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(fetchResp, fetchReq)
	if fetchResp.Code != http.StatusNotFound {
		t.Fatalf("expected missing blob after oversized reject, got %d", fetchResp.Code)
	}
}

func TestHandleRelay_AcceptsBodyAtLimit(t *testing.T) {
	store := storage.NewStore()
	ks := NewKeyStore(nil)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("1234")))
	req.Header.Set("X-Message-ID", "at-limit")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, 4, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for body at limit, got %d", rr.Code)
	}

	fetchReq := httptest.NewRequest(http.MethodGet, "/fetch?id=at-limit", nil)
	fetchResp := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(fetchResp, fetchReq)
	if fetchResp.Code != http.StatusOK {
		t.Fatalf("expected stored blob to be fetchable, got %d", fetchResp.Code)
	}
}

func TestHandleRelay_RejectsInvalidFixedCellSize(t *testing.T) {
	t.Setenv("RELAY_FIXED_CELL_BYTES", "16")

	store := storage.NewStore()
	ks := NewKeyStore(nil)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("short")))
	req.Header.Set("X-Message-ID", "fixed-invalid-size")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-cell sized payload, got %d", rr.Code)
	}
}

func TestHandleRelay_RejectsMalformedFixedCellLengthPrefix(t *testing.T) {
	t.Setenv("RELAY_FIXED_CELL_BYTES", "16")

	store := storage.NewStore()
	ks := NewKeyStore(nil)

	body := make([]byte, 16)
	binary.BigEndian.PutUint32(body[:4], uint32(20))

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "fixed-invalid-prefix")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed fixed cell prefix, got %d", rr.Code)
	}
}

func TestHandleRelay_RejectsMalformedFixedCellPadding(t *testing.T) {
	t.Setenv("RELAY_FIXED_CELL_BYTES", "16")

	store := storage.NewStore()
	ks := NewKeyStore(nil)

	body := make([]byte, 16)
	binary.BigEndian.PutUint32(body[:4], uint32(4))
	copy(body[4:8], []byte("ping"))
	body[8] = 1

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "fixed-invalid-padding")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed fixed cell padding, got %d", rr.Code)
	}
}

func TestHandleRelay_AcceptsValidFixedCell(t *testing.T) {
	t.Setenv("RELAY_FIXED_CELL_BYTES", "16")

	store := storage.NewStore()
	ks := NewKeyStore(nil)

	body := make([]byte, 16)
	binary.BigEndian.PutUint32(body[:4], uint32(4))
	copy(body[4:8], []byte("ping"))

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer(body))
	req.Header.Set("X-Message-ID", "fixed-valid")
	req.Header.Set("X-Receiver-ID", "bob")

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid fixed cell, got %d", rr.Code)
	}

	fetchReq := httptest.NewRequest(http.MethodGet, "/fetch?id=fixed-valid", nil)
	fetchResp := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(fetchResp, fetchReq)
	if fetchResp.Code != http.StatusOK {
		t.Fatalf("expected stored fixed cell to be fetchable, got %d", fetchResp.Code)
	}
	if !bytes.Equal(fetchResp.Body.Bytes(), body) {
		t.Fatalf("fetched fixed cell did not match stored payload")
	}
}

func TestHandleRelay_RejectsStaleTimestamp(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("payload")))
	req.Header.Set("X-Message-ID", "stale-msg")
	req.Header.Set("X-Receiver-ID", "bob")
	staleTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	setRequestAuthHeadersWithValues(
		req,
		key,
		"stale-msg",
		"bob",
		[]byte("payload"),
		staleTimestamp,
		nextTestNonce(),
	)

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale timestamp, got %d", rr.Code)
	}
}

func TestHandleRelay_RejectsReplayedNonce(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	handler := HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true)

	replayTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	replayNonce := nextTestNonce()

	req1 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello-1")))
	req1.Header.Set("X-Message-ID", "replay-1")
	req1.Header.Set("X-Receiver-ID", "bob")
	setRequestAuthHeadersWithValues(
		req1,
		key,
		"replay-1",
		"bob",
		[]byte("hello-1"),
		replayTimestamp,
		replayNonce,
	)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request should succeed, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello-2")))
	req2.Header.Set("X-Message-ID", "replay-2")
	req2.Header.Set("X-Receiver-ID", "bob")
	setRequestAuthHeadersWithValues(
		req2,
		key,
		"replay-2",
		"bob",
		[]byte("hello-2"),
		replayTimestamp,
		replayNonce,
	)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for replayed nonce, got %d", rr2.Code)
	}
}

func TestHandleFetch_RejectsStaleTimestamp(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)
	store.Store("fetch-stale", "user", []byte("blob"))

	req := httptest.NewRequest(http.MethodGet, "/fetch?id=fetch-stale", nil)
	staleTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	setRequestAuthHeadersWithValues(
		req,
		key,
		"fetch-stale",
		"",
		[]byte{},
		staleTimestamp,
		nextTestNonce(),
	)

	rr := httptest.NewRecorder()
	HandleFetch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale fetch request timestamp, got %d", rr.Code)
	}
}

func TestHandleMixMetrics_ReturnsSnapshot(t *testing.T) {
	forwarder := onion.NewMixForwarder(onion.MixForwardConfig{
		HopDelayMin:    5 * time.Millisecond,
		HopDelayMax:    15 * time.Millisecond,
		BatchWindow:    50 * time.Millisecond,
		BatchMax:       4,
		QueueCapacity:  8,
		ForwardTimeout: time.Second,
	})
	defer forwarder.Close()
	setCurrentMixForwarder(forwarder)

	req := httptest.NewRequest(http.MethodGet, "/metrics/mix", nil)
	rr := httptest.NewRecorder()
	HandleMixMetrics().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var snapshot onion.MixForwardMetrics
	if err := json.Unmarshal(rr.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode metrics snapshot: %v", err)
	}
	if snapshot.BatchWindowMS != 50 {
		t.Fatalf("expected batch window 50ms, got %d", snapshot.BatchWindowMS)
	}
	if snapshot.BatchMax != 4 {
		t.Fatalf("expected batch max 4, got %d", snapshot.BatchMax)
	}
	if snapshot.QueueCapacity != 8 {
		t.Fatalf("expected queue capacity 8, got %d", snapshot.QueueCapacity)
	}
}

func TestHandleChaffMetrics_ReturnsSnapshot(t *testing.T) {
	chaff := onion.NewRelayChaffGenerator(
		onion.RelayChaffConfig{
			Enabled:      true,
			IntervalMin:  500 * time.Millisecond,
			IntervalMax:  1000 * time.Millisecond,
			PayloadMin:   64,
			PayloadMax:   128,
			PathMinHops:  2,
			PathMaxHops:  3,
			BudgetPerMin: 40,
		},
		nil,
		nil,
	)
	setCurrentChaffGenerator(chaff)

	req := httptest.NewRequest(http.MethodGet, "/metrics/chaff", nil)
	rr := httptest.NewRecorder()
	HandleChaffMetrics().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var snapshot onion.RelayChaffMetrics
	if err := json.Unmarshal(rr.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode chaff metrics snapshot: %v", err)
	}
	if snapshot.BudgetPerMin != 40 {
		t.Fatalf("expected budget per min 40, got %d", snapshot.BudgetPerMin)
	}
	if snapshot.PayloadMinBytes != 64 || snapshot.PayloadMaxBytes != 128 {
		t.Fatalf("unexpected payload range in snapshot: min=%d max=%d", snapshot.PayloadMinBytes, snapshot.PayloadMaxBytes)
	}
}

func TestHandleRelay_RejectsExpiredRotatingMailboxHandle(t *testing.T) {
	t.Setenv("RELAY_MAILBOX_EPOCH_SEC", "60")
	t.Setenv("RELAY_MAILBOX_ACCEPT_PAST_EPOCHS", "0")
	t.Setenv("RELAY_MAILBOX_ACCEPT_FUTURE_EPOCHS", "0")

	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	oldEpoch := time.Now().Unix()/60 - 2
	receiver := rotatingMailboxHandle("bob", oldEpoch)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello")))
	req.Header.Set("X-Message-ID", "expired-mailbox")
	req.Header.Set("X-Receiver-ID", receiver)
	setRequestAuthHeaders(req, key, "expired-mailbox", receiver, []byte("hello"))

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired rotating mailbox handle, got %d", rr.Code)
	}
}

func TestHandleFetchPending_RejectsExpiredRotatingMailboxHandle(t *testing.T) {
	t.Setenv("RELAY_MAILBOX_EPOCH_SEC", "60")
	t.Setenv("RELAY_MAILBOX_ACCEPT_PAST_EPOCHS", "0")
	t.Setenv("RELAY_MAILBOX_ACCEPT_FUTURE_EPOCHS", "0")

	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	oldEpoch := time.Now().Unix()/60 - 2
	receiver := rotatingMailboxHandle("bob", oldEpoch)
	store.Store("m1", receiver, []byte("cipher"))

	req := httptest.NewRequest(http.MethodGet, "/fetch_pending?receiver="+receiver, nil)
	setRequestAuthHeaders(req, key, "", receiver, []byte{})
	rr := httptest.NewRecorder()
	HandleFetchPending(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired rotating mailbox handle, got %d", rr.Code)
	}
}

func TestHandleRelay_RejectsLegacyMailboxHandleAfterSunset(t *testing.T) {
	t.Setenv("RELAY_MAILBOX_ALLOW_LEGACY", "1")
	t.Setenv("RELAY_MAILBOX_LEGACY_UNTIL_UNIX", strconv.FormatInt(time.Now().Unix()-1, 10))

	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	req := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewBuffer([]byte("hello")))
	req.Header.Set("X-Message-ID", "legacy-expired")
	req.Header.Set("X-Receiver-ID", "legacy-static-receiver")
	setRequestAuthHeaders(
		req,
		key,
		"legacy-expired",
		"legacy-static-receiver",
		[]byte("hello"),
	)

	rr := httptest.NewRecorder()
	HandleRelay(store, ks, NewCredentialStore(time.Hour), false, 100, testMaxBlobBytes, nil, true).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when legacy mailbox handles are expired, got %d", rr.Code)
	}
}

func TestHandleFetchPendingBatch_ReturnsEnvelopeAndResponseHMAC(t *testing.T) {
	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	epoch := time.Now().Unix() / 300
	receiverHit := rotatingMailboxHandle("alice", epoch)
	receiverMiss := rotatingMailboxHandle("bob", epoch)
	store.Store("m-batch-1", receiverHit, []byte("cipher"))

	reqBody, err := json.Marshal(map[string][]string{
		"receivers": []string{receiverHit, receiverMiss},
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/fetch_pending_batch", bytes.NewBuffer(reqBody))
	setRequestAuthHeaders(req, key, "", "", reqBody)
	rr := httptest.NewRecorder()
	HandleFetchPendingBatch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from batch fetch, got %d", rr.Code)
	}

	if got, want := rr.Header().Get("X-HMAC"), computeHMACBytes(key, rr.Body.Bytes()); got != want {
		t.Fatalf("batch response HMAC mismatch")
	}

	type result struct {
		Receiver string `json:"receiver"`
		Hit      bool   `json:"hit"`
		ID       string `json:"id"`
		Blob     string `json:"blob_base64"`
	}
	type response struct {
		Envelope string   `json:"envelope"`
		Results  []result `json:"results"`
	}
	var parsed response
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	if parsed.Envelope != "fetch_pending_batch_v1" {
		t.Fatalf("unexpected batch envelope: %s", parsed.Envelope)
	}
	if len(parsed.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(parsed.Results))
	}
	if !parsed.Results[0].Hit || parsed.Results[0].Receiver != receiverHit || parsed.Results[0].ID != "m-batch-1" {
		t.Fatalf("unexpected first batch result: %+v", parsed.Results[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(parsed.Results[0].Blob)
	if err != nil || string(decoded) != "cipher" {
		t.Fatalf("unexpected first batch blob decode")
	}
	if parsed.Results[1].Hit || parsed.Results[1].Receiver != receiverMiss {
		t.Fatalf("unexpected second batch result: %+v", parsed.Results[1])
	}
}

func TestHandleFetchPendingBatch_RejectsLegacyHandleWhenLegacyDisabled(t *testing.T) {
	t.Setenv("RELAY_MAILBOX_ALLOW_LEGACY", "0")

	key := []byte("supersecretkey0123456789012345")
	store := storage.NewStore()
	ks := NewKeyStore(key)

	reqBody, err := json.Marshal(map[string][]string{
		"receivers": []string{"legacy-static-receiver"},
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/fetch_pending_batch", bytes.NewBuffer(reqBody))
	setRequestAuthHeaders(req, key, "", "", reqBody)
	rr := httptest.NewRecorder()
	HandleFetchPendingBatch(store, ks, NewCredentialStore(time.Hour), false).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when legacy mailbox handle is disabled, got %d", rr.Code)
	}
}
