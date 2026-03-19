package network

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"redoor-relay/src/onion"
	"redoor-relay/src/storage"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mixMetricsMu        sync.RWMutex
	currentMixForwarder *onion.MixForwarder
	currentChaffGen     *onion.RelayChaffGenerator
)

const (
	mailboxHandleVersion             = "mb1"
	defaultMailboxEpochSec           = int64(300)
	defaultMailboxAcceptPastEpochs   = int64(2)
	defaultMailboxAcceptFutureEpochs = int64(1)
	defaultMailboxBatchMaxReceivers  = 16
)

type mailboxHandlePolicy struct {
	epochSec         int64
	acceptPastEpochs int64
	acceptFuture     int64
	allowLegacy      bool
	legacyUntilUnix  int64
}

func setCurrentMixForwarder(forwarder *onion.MixForwarder) {
	mixMetricsMu.Lock()
	currentMixForwarder = forwarder
	mixMetricsMu.Unlock()
}

func getCurrentMixForwarder() *onion.MixForwarder {
	mixMetricsMu.RLock()
	defer mixMetricsMu.RUnlock()
	return currentMixForwarder
}

func setCurrentChaffGenerator(generator *onion.RelayChaffGenerator) {
	mixMetricsMu.Lock()
	currentChaffGen = generator
	mixMetricsMu.Unlock()
}

func getCurrentChaffGenerator() *onion.RelayChaffGenerator {
	mixMetricsMu.RLock()
	defer mixMetricsMu.RUnlock()
	return currentChaffGen
}

func newMailboxHandlePolicyFromEnv() mailboxHandlePolicy {
	epochSec := int64(parseMailboxIntEnv("RELAY_MAILBOX_EPOCH_SEC", int(defaultMailboxEpochSec)))
	if epochSec <= 0 {
		epochSec = defaultMailboxEpochSec
	}

	acceptPast := int64(parseMailboxIntEnv("RELAY_MAILBOX_ACCEPT_PAST_EPOCHS", int(defaultMailboxAcceptPastEpochs)))
	if acceptPast < 0 {
		acceptPast = defaultMailboxAcceptPastEpochs
	}

	acceptFuture := int64(parseMailboxIntEnv("RELAY_MAILBOX_ACCEPT_FUTURE_EPOCHS", int(defaultMailboxAcceptFutureEpochs)))
	if acceptFuture < 0 {
		acceptFuture = defaultMailboxAcceptFutureEpochs
	}

	allowLegacy := os.Getenv("RELAY_MAILBOX_ALLOW_LEGACY") != "0"
	legacyUntilUnix := int64(0)
	if raw := strings.TrimSpace(os.Getenv("RELAY_MAILBOX_LEGACY_UNTIL_UNIX")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			legacyUntilUnix = parsed
		}
	}

	return mailboxHandlePolicy{
		epochSec:         epochSec,
		acceptPastEpochs: acceptPast,
		acceptFuture:     acceptFuture,
		allowLegacy:      allowLegacy,
		legacyUntilUnix:  legacyUntilUnix,
	}
}

func parseMailboxIntEnv(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func (p mailboxHandlePolicy) validate(receiver string, now time.Time) error {
	if receiver == "" {
		return fmt.Errorf("missing receiver")
	}

	// Reserved namespaces remain fixed.
	if receiver == "public" || strings.HasPrefix(receiver, "__") {
		return nil
	}

	if strings.HasPrefix(receiver, mailboxHandleVersion+"_") {
		parts := strings.SplitN(receiver, "_", 3)
		if len(parts) != 3 {
			return fmt.Errorf("invalid mailbox handle format")
		}

		epoch, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || epoch <= 0 {
			return fmt.Errorf("invalid mailbox handle epoch")
		}

		hashPart := parts[2]
		if len(hashPart) != 64 {
			return fmt.Errorf("invalid mailbox handle hash length")
		}
		if _, err := hex.DecodeString(hashPart); err != nil {
			return fmt.Errorf("invalid mailbox handle hash")
		}

		currentEpoch := now.Unix() / p.epochSec
		minEpoch := currentEpoch - p.acceptPastEpochs
		maxEpoch := currentEpoch + p.acceptFuture
		if epoch < minEpoch || epoch > maxEpoch {
			return fmt.Errorf("mailbox handle expired")
		}
		return nil
	}

	// Backward-compatible static blinded handles are optionally allowed.
	if !p.allowLegacy {
		return fmt.Errorf("legacy mailbox handles disabled")
	}
	if p.legacyUntilUnix > 0 && now.Unix() > p.legacyUntilUnix {
		return fmt.Errorf("legacy mailbox handles expired")
	}
	return nil
}

// HandleRelay returns a handler for storing blobs or forwarding via mixnet.
func HandleRelay(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	maxPending int,
	maxBlobBytes int,
	nextHops []string,
	isExit bool,
) http.HandlerFunc {
	return HandleRelayWithAbuse(
		store,
		ks,
		creds,
		requireScopedAuth,
		maxPending,
		maxBlobBytes,
		nextHops,
		isExit,
		nil,
	)
}

// HandleRelayWithAbuse extends relay handling with per-client/per-receiver abuse controls.
func HandleRelayWithAbuse(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	maxPending int,
	maxBlobBytes int,
	nextHops []string,
	isExit bool,
	abuse *AbuseController,
) http.HandlerFunc {
	replay := newReplayProtectorFromEnv()
	mailboxPolicy := newMailboxHandlePolicyFromEnv()
	_, mixEnabled, mixKeyErr := onion.LoadMixPrivateKeyFromEnv()
	mixParser := mixPacketParser(unavailableMixPacketParser{})
	if mixEnabled {
		mixParser = newMixPacketParserFromEnv()
	}
	mixForwarder := onion.NewMixForwarderFromEnv()
	chaffGenerator := onion.NewRelayChaffGeneratorFromEnv(mixForwarder)
	setCurrentMixForwarder(mixForwarder)
	setCurrentChaffGenerator(chaffGenerator)
	chaffGenerator.Start()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		maybeDelay()

		msgID := r.Header.Get("X-Message-ID")
		receiverID := r.Header.Get("X-Receiver-ID")
		if msgID == "" || receiverID == "" {
			RecordMalformedSignal()
			http.Error(w, "Missing X-Message-ID or X-Receiver-ID header", http.StatusBadRequest)
			return
		}
		if err := mailboxPolicy.validate(receiverID, time.Now()); err != nil {
			RecordMalformedSignal()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		body, err := readBodyWithLimit(r.Body, maxBlobBytes)
		if err != nil {
			if err == errBodyTooLarge {
				RecordMalformedSignal()
				http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
				return
			}
			RecordMalformedSignal()
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		if err := validateFixedTransportCell(body); err != nil {
			RecordMalformedSignal()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if status, msg := authorizeRequest(
			r,
			ks,
			creds,
			requireScopedAuth,
			replay,
			r.Method,
			r.URL.Path,
			msgID,
			receiverID,
			body,
		); status != 0 {
			http.Error(w, msg, status)
			return
		}

		pendingCount := store.Count(receiverID)
		if !abuse.enforce(w, r, receiverID, pendingCount) {
			return
		}

		// Special-case: cover traffic is immediately acknowledged and dropped.
		if receiverID == "__cover__" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// New Sphinx-like mix packet processing path.
		if receiverID == "__mix__" {
			if mixKeyErr != nil {
				http.Error(w, "mix key configuration error", http.StatusInternalServerError)
				return
			}
			if !mixEnabled {
				http.Error(w, "mix processing unavailable on this relay", http.StatusServiceUnavailable)
				return
			}

			result, err := mixParser.Process(body)
			if err != nil {
				if errors.Is(err, errParserWorkerUnavailable) {
					http.Error(w, "mix parser worker unavailable", http.StatusServiceUnavailable)
					return
				}
				switch {
				case errors.Is(err, onion.ErrReplayTag):
					http.Error(w, err.Error(), http.StatusUnauthorized)
				case errors.Is(err, onion.ErrNotMixPacket):
					http.Error(w, err.Error(), http.StatusBadRequest)
				default:
					http.Error(w, "invalid mix packet", http.StatusBadRequest)
				}
				return
			}

			if result.Forwarded {
				if err := mixForwarder.Forward(result.NextHop, msgID, result.Payload); err != nil {
					http.Error(w, "mix forward failed", http.StatusBadGateway)
					return
				}
				w.WriteHeader(http.StatusOK)
				return
			}

			if result.Final {
				if result.ReceiverID == "__cover__" {
					w.WriteHeader(http.StatusOK)
					return
				}
				if err := mailboxPolicy.validate(result.ReceiverID, time.Now()); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				// Enforce per-receiver quota on final destination.
				finalPending := store.Count(result.ReceiverID)
				if maxPending > 0 && finalPending >= maxPending {
					http.Error(w, "Receiver quota exceeded", http.StatusTooManyRequests)
					return
				}

				store.Store(msgID, result.ReceiverID, result.Payload)
				w.WriteHeader(http.StatusOK)
				return
			}

			http.Error(w, "invalid mix processing result", http.StatusBadRequest)
			return
		}

		// If this relay is configured as a mix hop, forward instead of storing.
		if len(nextHops) > 0 && !isExit {
			// Select a hop at random to make traffic less linkable.
			target := nextHops[rand.Intn(len(nextHops))]
			err := onion.MixAndForward(target, msgID, receiverID, body)
			if err != nil {
				http.Error(w, "mix forward failed", http.StatusBadGateway)
				return
			}
		} else {
			persistent := isPersistentRequested(r.Header.Get("X-Persistent"))
			if persistent && receiverID != "public" {
				http.Error(w, "X-Persistent is only allowed for receiver=public", http.StatusBadRequest)
				return
			}

			// Per-receiver quota
			if !persistent && maxPending > 0 && pendingCount >= maxPending {
				http.Error(w, "Receiver quota exceeded", http.StatusTooManyRequests)
				return
			}

			if persistent {
				store.StorePersistent(msgID, body)
			} else {
				store.Store(msgID, receiverID, body)
			}

			if key := ks.Get(); len(key) > 0 && !hasScopedAuthHeaders(r) {
				serverMAC := computeHMAC(key, msgID, receiverID, body)
				w.Header().Set("X-HMAC", serverMAC)
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

// HandleMixMetrics reports mix-forward batching and queue-delay metrics.
func HandleMixMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		forwarder := getCurrentMixForwarder()
		snapshot := onion.MixForwardMetrics{}
		if forwarder != nil {
			snapshot = forwarder.MetricsSnapshot()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
			return
		}
	}
}

// HandleChaffMetrics reports relay-generated chaff behavior and budget outcomes.
func HandleChaffMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		generator := getCurrentChaffGenerator()
		snapshot := onion.RelayChaffMetrics{}
		if generator != nil {
			snapshot = generator.MetricsSnapshot()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
			return
		}
	}
}

var errBodyTooLarge = fmt.Errorf("body too large")

func readBodyWithLimit(body io.ReadCloser, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(body)
	}

	defer body.Close()
	limited := io.LimitReader(body, int64(maxBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, errBodyTooLarge
	}
	return data, nil
}

// HandleFetch returns a handler for retrieving blobs.
func HandleFetch(store *storage.EphemeralStore, ks *KeyStore, creds *CredentialStore, requireScopedAuth bool) http.HandlerFunc {
	return HandleFetchWithAbuse(store, ks, creds, requireScopedAuth, nil)
}

func HandleFetchWithAbuse(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	abuse *AbuseController,
) http.HandlerFunc {
	replay := newReplayProtectorFromEnv()

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		maybeDelay()

		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing ID parameter", http.StatusBadRequest)
			return
		}

		if status, msg := authorizeRequest(
			r,
			ks,
			creds,
			requireScopedAuth,
			replay,
			r.Method,
			r.URL.Path,
			id,
			"",
			[]byte{},
		); status != 0 {
			http.Error(w, msg, status)
			return
		}

		if !abuse.enforce(w, r, "", 0) {
			return
		}

		data, exists := store.Retrieve(id)
		if !exists {
			http.Error(w, "Blob not found", http.StatusNotFound)
			return
		}

		// Optional padding for size obfuscation
		pad := maybePadBytes()
		if pad != nil {
			w.Header().Set("X-Pad-Len", fmt.Sprintf("%d", len(pad)))
			data = append(data, pad...)
		}

		if key := ks.Get(); len(key) > 0 && !hasScopedAuthHeaders(r) {
			mac := computeHMAC(key, id, "", data) // receiver unknown in direct fetch
			w.Header().Set("X-HMAC", mac)
		}

		if _, err := w.Write(data); err != nil {
			return
		}
	}
}

// HandleFetchPending returns the next blob for a receiver.
func HandleFetchPending(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
) http.HandlerFunc {
	return HandleFetchPendingWithAbuse(store, ks, creds, requireScopedAuth, nil)
}

func HandleFetchPendingWithAbuse(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	abuse *AbuseController,
) http.HandlerFunc {
	replay := newReplayProtectorFromEnv()
	mailboxPolicy := newMailboxHandlePolicyFromEnv()

	type response struct {
		Envelope string `json:"envelope"`
		Receiver string `json:"receiver"`
		Hit      bool   `json:"hit"`
		ID       string `json:"id"`
		Blob     string `json:"blob_base64"`
		Pad      string `json:"pad_base64,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		maybeDelay()

		receiver := r.URL.Query().Get("receiver")
		if receiver == "" {
			http.Error(w, "Missing receiver parameter", http.StatusBadRequest)
			return
		}
		if err := mailboxPolicy.validate(receiver, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if status, msg := authorizeRequest(
			r,
			ks,
			creds,
			requireScopedAuth,
			replay,
			r.Method,
			r.URL.Path,
			"",
			receiver,
			[]byte{},
		); status != 0 {
			http.Error(w, msg, status)
			return
		}

		pendingCount := store.Count(receiver)
		if !abuse.enforce(w, r, receiver, pendingCount) {
			return
		}

		id, data, ok := store.RetrieveNextByReceiver(receiver)
		if !ok {
			http.Error(w, "No pending blobs for receiver", http.StatusNotFound)
			return
		}

		resp := response{
			Envelope: "fetch_pending_v1",
			Receiver: receiver,
			Hit:      true,
			ID:       id,
			Blob:     base64.StdEncoding.EncodeToString(data),
		}
		if pad := maybePadBytes(); len(pad) > 0 {
			resp.Pad = base64.StdEncoding.EncodeToString(pad)
		}

		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}

		if key := ks.Get(); len(key) > 0 && !hasScopedAuthHeaders(r) {
			h := computeHMACBytes(key, respBytes)
			w.Header().Set("X-HMAC", h)
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(respBytes); err != nil {
			return
		}
	}
}

// HandleFetchPendingBatch returns a normalized envelope for a set of mailbox handles.
func HandleFetchPendingBatch(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
) http.HandlerFunc {
	return HandleFetchPendingBatchWithAbuse(store, ks, creds, requireScopedAuth, nil)
}

// HandleFetchPendingBatchWithAbuse processes a batch mailbox request with optional abuse controls.
func HandleFetchPendingBatchWithAbuse(
	store *storage.EphemeralStore,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	abuse *AbuseController,
) http.HandlerFunc {
	replay := newReplayProtectorFromEnv()
	mailboxPolicy := newMailboxHandlePolicyFromEnv()
	maxReceivers := parseMailboxIntEnv("RELAY_FETCH_PENDING_BATCH_MAX_RECEIVERS", defaultMailboxBatchMaxReceivers)
	if maxReceivers <= 0 {
		maxReceivers = defaultMailboxBatchMaxReceivers
	}

	type batchRequest struct {
		Receivers []string `json:"receivers"`
	}

	type batchResult struct {
		Receiver string `json:"receiver"`
		Hit      bool   `json:"hit"`
		ID       string `json:"id,omitempty"`
		Blob     string `json:"blob_base64,omitempty"`
	}

	type batchResponse struct {
		Envelope string        `json:"envelope"`
		Results  []batchResult `json:"results"`
		Pad      string        `json:"pad_base64,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		maybeDelay()

		body, err := readBodyWithLimit(r.Body, 64*1024)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var req batchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if len(req.Receivers) == 0 {
			http.Error(w, "Missing receivers", http.StatusBadRequest)
			return
		}
		if len(req.Receivers) > maxReceivers {
			http.Error(w, "Too many receivers", http.StatusBadRequest)
			return
		}

		normalized := make([]string, 0, len(req.Receivers))
		for _, receiver := range req.Receivers {
			receiver = strings.TrimSpace(receiver)
			if receiver == "" {
				http.Error(w, "Empty receiver value", http.StatusBadRequest)
				return
			}
			if err := mailboxPolicy.validate(receiver, time.Now()); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			normalized = append(normalized, receiver)
		}

		if status, msg := authorizeRequest(
			r,
			ks,
			creds,
			requireScopedAuth,
			replay,
			r.Method,
			r.URL.Path,
			"",
			"",
			body,
		); status != 0 {
			http.Error(w, msg, status)
			return
		}

		results := make([]batchResult, 0, len(normalized))
		for _, receiver := range normalized {
			pendingCount := store.Count(receiver)
			if !abuse.enforce(w, r, receiver, pendingCount) {
				return
			}

			id, data, ok := store.RetrieveNextByReceiver(receiver)
			if !ok {
				results = append(results, batchResult{
					Receiver: receiver,
					Hit:      false,
				})
				continue
			}
			results = append(results, batchResult{
				Receiver: receiver,
				Hit:      true,
				ID:       id,
				Blob:     base64.StdEncoding.EncodeToString(data),
			})
		}

		resp := batchResponse{
			Envelope: "fetch_pending_batch_v1",
			Results:  results,
		}
		if pad := maybePadBytes(); len(pad) > 0 {
			resp.Pad = base64.StdEncoding.EncodeToString(pad)
		}

		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}

		if key := ks.Get(); len(key) > 0 && !hasScopedAuthHeaders(r) {
			h := computeHMACBytes(key, respBytes)
			w.Header().Set("X-HMAC", h)
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(respBytes); err != nil {
			return
		}
	}
}

func computeHMAC(key []byte, id string, receiver string, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	mac.Write([]byte(receiver))
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func computeRequestHMAC(
	key []byte,
	id string,
	receiver string,
	data []byte,
	timestamp string,
	nonce string,
) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	mac.Write([]byte(id))
	mac.Write([]byte(receiver))
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func computeHMACBytes(key []byte, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyHMACB64(provided, expected string) bool {
	providedRaw, err := base64.StdEncoding.DecodeString(provided)
	if err != nil {
		return false
	}
	expectedRaw, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(providedRaw, expectedRaw)
}

// HandleAuthRegister issues anonymous scoped client credentials.
func HandleAuthRegister(creds *CredentialStore) http.HandlerFunc {
	type registerRequest struct {
		BlindNonceB64 string `json:"blind_nonce_b64"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if creds == nil {
			http.Error(w, "Credential store unavailable", http.StatusInternalServerError)
			return
		}

		var blindNonce []byte
		if r.ContentLength != 0 {
			body, err := readBodyWithLimit(r.Body, 4*1024)
			if err != nil {
				if errors.Is(err, errBodyTooLarge) {
					http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			if len(body) > 0 {
				var req registerRequest
				if err := json.Unmarshal(body, &req); err != nil {
					http.Error(w, "Invalid JSON body", http.StatusBadRequest)
					return
				}
				if strings.TrimSpace(req.BlindNonceB64) != "" {
					decoded, err := base64.StdEncoding.DecodeString(req.BlindNonceB64)
					if err != nil {
						http.Error(w, "Invalid blind nonce encoding", http.StatusBadRequest)
						return
					}
					if len(decoded) == 0 || len(decoded) > 256 {
						http.Error(w, "Invalid blind nonce size", http.StatusBadRequest)
						return
					}
					blindNonce = decoded
				}
			}
		}

		cred, err := creds.IssueWithBlind(blindNonce)
		if err != nil {
			http.Error(w, "Failed to issue credential", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(creds.ToResponse(cred)); err != nil {
			http.Error(w, "Failed to encode credential response", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAuthRefresh rotates a scoped credential for an authenticated client.
func HandleAuthRefresh(creds *CredentialStore) http.HandlerFunc {
	replay := newReplayProtectorFromEnv()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if creds == nil {
			http.Error(w, "Credential store unavailable", http.StatusInternalServerError)
			return
		}

		if status, msg := authorizeRequest(
			r,
			nil,
			creds,
			true,
			replay,
			r.Method,
			r.URL.Path,
			"",
			"",
			[]byte{},
		); status != 0 {
			http.Error(w, msg, status)
			return
		}

		oldClientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
		if token := strings.TrimSpace(r.Header.Get("X-Scoped-Token")); token != "" {
			tokenSig := strings.TrimSpace(r.Header.Get("X-Scoped-Token-Signature"))
			oldClientID = scopedTokenFingerprint(token, tokenSig)
		}
		cred, replaced, err := creds.Replace(oldClientID)
		if err != nil {
			http.Error(w, "Failed to issue credential", http.StatusInternalServerError)
			return
		}
		if !replaced {
			http.Error(w, "invalid or expired scoped credential", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(creds.ToResponse(cred)); err != nil {
			http.Error(w, "Failed to encode credential response", http.StatusInternalServerError)
			return
		}
	}
}

type revocationRequest struct {
	ClientID         string `json:"client_id"`
	TokenFingerprint string `json:"token_fingerprint"`
}

// HandleAuthRevoke revokes a scoped credential immediately.
func HandleAuthRevoke(creds *CredentialStore, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if creds == nil {
			http.Error(w, "Credential store unavailable", http.StatusInternalServerError)
			return
		}
		if !adminTokenAuthorized(r.Header.Get("X-Admin-Token"), adminToken) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req revocationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		clientID := strings.TrimSpace(req.TokenFingerprint)
		if clientID == "" {
			clientID = strings.TrimSpace(req.ClientID)
		}
		if clientID == "" {
			http.Error(w, "Missing token_fingerprint or client_id", http.StatusBadRequest)
			return
		}
		if !creds.Revoke(clientID) {
			http.Error(w, "Credential not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

type rotationRequest struct {
	OverlapSec int64 `json:"overlap_sec"`
}

// HandleAuthRotate activates a new credential generation with overlap.
func HandleAuthRotate(
	creds *CredentialStore,
	adminToken string,
	defaultOverlap time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if creds == nil {
			http.Error(w, "Credential store unavailable", http.StatusInternalServerError)
			return
		}
		if !adminTokenAuthorized(r.Header.Get("X-Admin-Token"), adminToken) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		overlap := defaultOverlap
		if r.ContentLength > 0 {
			var req rotationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}
			if req.OverlapSec > 0 {
				overlap = time.Duration(req.OverlapSec) * time.Second
			}
		}

		rotation := creds.Rotate(overlap)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(rotation); err != nil {
			http.Error(w, "Failed to encode rotation response", http.StatusInternalServerError)
			return
		}
	}
}

func hasScopedAuthHeaders(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("X-Scoped-Token")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Scoped-Request-Signature")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Client-ID")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Client-Signature")) != ""
}

func authorizeRequest(
	r *http.Request,
	ks *KeyStore,
	creds *CredentialStore,
	requireScopedAuth bool,
	replay *replayProtector,
	method string,
	path string,
	id string,
	receiver string,
	body []byte,
) (int, string) {
	scopedToken := strings.TrimSpace(r.Header.Get("X-Scoped-Token"))
	scopedTokenSig := strings.TrimSpace(r.Header.Get("X-Scoped-Token-Signature"))
	scopedReqSig := strings.TrimSpace(r.Header.Get("X-Scoped-Request-Signature"))
	scopedTS := strings.TrimSpace(r.Header.Get("X-Scoped-Timestamp"))
	scopedNonce := strings.TrimSpace(r.Header.Get("X-Scoped-Nonce"))

	if scopedToken != "" || scopedTokenSig != "" || scopedReqSig != "" || scopedTS != "" || scopedNonce != "" {
		if scopedToken == "" || scopedTokenSig == "" || scopedReqSig == "" || scopedTS == "" || scopedNonce == "" {
			RecordMalformedSignal()
			return http.StatusBadRequest, "missing scoped token auth header"
		}
		if creds == nil {
			return http.StatusInternalServerError, "scoped auth unavailable"
		}
		clientID := scopedTokenFingerprint(scopedToken, scopedTokenSig)
		if err := replay.validateWithScope("scoped:"+clientID, scopedTS, scopedNonce); err != nil {
			RecordReplaySignal()
			status, msg := statusForReplayError(err)
			return status, msg
		}
		cred, ok := creds.ValidateScopedToken(scopedToken, scopedTokenSig)
		if !ok {
			RecordCredentialSpraySignal()
			return http.StatusUnauthorized, "invalid or expired scoped token"
		}
		expected := computeScopedRequestSignature(
			cred.Secret,
			clientID,
			method,
			path,
			id,
			receiver,
			body,
			scopedTS,
			scopedNonce,
		)
		if !verifyHMACB64(scopedReqSig, expected) {
			RecordCredentialSpraySignal()
			return http.StatusUnauthorized, "invalid scoped token request signature"
		}
		return 0, ""
	}

	clientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
	clientSig := strings.TrimSpace(r.Header.Get("X-Client-Signature"))
	clientTS := strings.TrimSpace(r.Header.Get("X-Client-Timestamp"))
	clientNonce := strings.TrimSpace(r.Header.Get("X-Client-Nonce"))

	if clientID != "" || clientSig != "" || clientTS != "" || clientNonce != "" {
		if clientID == "" || clientSig == "" || clientTS == "" || clientNonce == "" {
			RecordMalformedSignal()
			return http.StatusBadRequest, "missing scoped auth header"
		}
		if creds == nil {
			return http.StatusInternalServerError, "scoped auth unavailable"
		}
		if err := replay.validateWithScope(clientID, clientTS, clientNonce); err != nil {
			RecordReplaySignal()
			status, msg := statusForReplayError(err)
			return status, msg
		}
		cred, ok := creds.Get(clientID)
		if !ok {
			RecordCredentialSpraySignal()
			return http.StatusUnauthorized, "invalid or expired scoped credential"
		}
		expected := computeScopedRequestSignature(
			cred.Secret,
			clientID,
			method,
			path,
			id,
			receiver,
			body,
			clientTS,
			clientNonce,
		)
		if !verifyHMACB64(clientSig, expected) {
			RecordCredentialSpraySignal()
			return http.StatusUnauthorized, "invalid scoped signature"
		}
		return 0, ""
	}

	if requireScopedAuth {
		RecordCredentialSpraySignal()
		return http.StatusUnauthorized, "scoped auth required"
	}

	if ks != nil {
		if key := ks.Get(); len(key) > 0 {
			timestamp := r.Header.Get("X-HMAC-Timestamp")
			nonce := r.Header.Get("X-HMAC-Nonce")
			if err := replay.validateWithScope("legacy", timestamp, nonce); err != nil {
				RecordReplaySignal()
				status, msg := statusForReplayError(err)
				return status, msg
			}

			clientMAC := r.Header.Get("X-HMAC")
			if clientMAC == "" {
				RecordMalformedSignal()
				return http.StatusBadRequest, "Missing X-HMAC header"
			}
			expected := computeRequestHMAC(key, id, receiver, body, timestamp, nonce)
			if !verifyHMACB64(clientMAC, expected) {
				RecordCredentialSpraySignal()
				return http.StatusUnauthorized, "Invalid HMAC"
			}
		}
	}

	return 0, ""
}

func adminTokenAuthorized(provided, expected string) bool {
	return expected != "" && subtleConstantTimeCompare(provided, expected)
}

func subtleConstantTimeCompare(provided, expected string) bool {
	// avoid importing crypto/subtle into all call sites by keeping this helper local.
	if len(provided) != len(expected) {
		return false
	}
	var result byte
	for i := 0; i < len(provided); i++ {
		result |= provided[i] ^ expected[i]
	}
	return result == 0
}

func computeScopedRequestSignature(
	secret []byte,
	clientID string,
	method string,
	path string,
	id string,
	receiver string,
	body []byte,
	timestamp string,
	nonce string,
) string {
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		timestamp,
		nonce,
		clientID,
		strings.ToUpper(method),
		path,
		id,
		receiver,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func maybeDelay() {
	minMS := envUint("RELAY_DELAY_MIN_MS")
	maxMS := envUint("RELAY_DELAY_MAX_MS")
	if maxMS == 0 {
		return
	}
	if minMS > maxMS {
		minMS = maxMS
	}
	delta := maxMS - minMS
	delay := minMS
	if delta > 0 {
		delay += uint64(rand.Int63n(int64(delta) + 1))
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func envUint(key string) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func isPersistentRequested(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func validateFixedTransportCell(body []byte) error {
	cellBytes := envUint("RELAY_FIXED_CELL_BYTES")
	if cellBytes == 0 {
		return nil
	}
	if cellBytes < 4 {
		return fmt.Errorf("invalid RELAY_FIXED_CELL_BYTES: must be >= 4")
	}
	if len(body) != int(cellBytes) {
		return fmt.Errorf("invalid transport cell size")
	}

	payloadLen := int(binary.BigEndian.Uint32(body[:4]))
	maxPayloadLen := int(cellBytes) - 4
	if payloadLen > maxPayloadLen {
		return fmt.Errorf("malformed transport cell payload length")
	}

	for _, b := range body[4+payloadLen:] {
		if b != 0 {
			return fmt.Errorf("malformed transport cell padding")
		}
	}

	return nil
}

// maybePadBytes returns a random padding blob if RELAY_PAD_RESP_B64 > 0.
// The length is uniform between 1 and PAD, to avoid predictable boundaries.
func maybePadBytes() []byte {
	padTo := envUint("RELAY_PAD_RESP_BYTES")
	if padTo == 0 {
		return nil
	}
	if padTo > 64*1024 {
		padTo = 64 * 1024 // sanity cap
	}
	padLen := rand.Intn(int(padTo)) + 1
	buf := make([]byte, padLen)
	if _, err := crand.Read(buf); err != nil {
		return nil
	}
	return buf
}
