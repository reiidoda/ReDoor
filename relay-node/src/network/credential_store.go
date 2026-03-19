package network

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	defaultCredentialTTL        = time.Hour
	defaultCredentialSecretSize = 32
	defaultRotationOverlap      = 5 * time.Minute
	scopedTokenVersion          = uint64(1)
)

var errCredentialGenerationUnavailable = errors.New("credential generation unavailable")

type scopedTokenClaims struct {
	Version    uint64 `json:"v"`
	TokenID    string `json:"tid"`
	BlindHash  string `json:"bh,omitempty"`
	ExpiresAt  int64  `json:"exp"`
	Generation uint64 `json:"gen"`
}

// ClientCredential is an anonymous scoped auth credential for relay requests.
type ClientCredential struct {
	ClientID          string
	ScopedToken       string
	ScopedTokenSigB64 string
	Secret            []byte
	ExpiresAt         time.Time
	Generation        uint64
	BlindHash         string
	RevokedAt         time.Time
}

// RegistrationResponse is returned by /auth/register.
type RegistrationResponse struct {
	ScopedToken       string `json:"scoped_token"`
	ScopedTokenSigB64 string `json:"scoped_token_sig_b64"`
	TokenSecretB64    string `json:"token_secret_b64"`
	TokenFingerprint  string `json:"token_fingerprint"`
	BlindHash         string `json:"blind_hash,omitempty"`
	ExpiresAt         int64  `json:"expires_at"`
	CredentialVersion uint64 `json:"credential_version"`

	// Compatibility fields for older clients.
	ClientID        string `json:"client_id,omitempty"`
	ClientSecretB64 string `json:"client_secret_b64,omitempty"`
}

// RotationResponse reports active/previous credential versions.
type RotationResponse struct {
	ActiveVersion   uint64 `json:"active_version"`
	PreviousVersion uint64 `json:"previous_version"`
	OverlapEndsAt   int64  `json:"overlap_ends_at"`
}

// CredentialStore holds in-memory scoped credentials with TTL.
type CredentialStore struct {
	ttl                time.Duration
	rotationOverlap    time.Duration
	mu                 sync.RWMutex
	data               map[string]ClientCredential
	signingKeys        map[uint64][]byte
	activeGeneration   uint64
	previousGeneration uint64
	previousValidUntil time.Time
}

func NewCredentialStore(ttl time.Duration) *CredentialStore {
	if ttl <= 0 {
		ttl = defaultCredentialTTL
	}
	store := &CredentialStore{
		ttl:              ttl,
		rotationOverlap:  defaultRotationOverlap,
		data:             make(map[string]ClientCredential),
		signingKeys:      make(map[uint64][]byte),
		activeGeneration: 1,
	}
	store.signingKeys[store.activeGeneration] = generateScopedTokenSigningKey()
	go store.cleanupLoop()
	return store
}

func (cs *CredentialStore) Issue() (ClientCredential, error) {
	return cs.IssueWithBlind(nil)
}

func (cs *CredentialStore) IssueWithBlind(blindNonce []byte) (ClientCredential, error) {
	idBytes := make([]byte, 16)
	if _, err := crand.Read(idBytes); err != nil {
		return ClientCredential{}, err
	}
	secret := make([]byte, defaultCredentialSecretSize)
	if _, err := crand.Read(secret); err != nil {
		return ClientCredential{}, err
	}

	generation := cs.currentGeneration()
	blindHash := ""
	if len(blindNonce) > 0 {
		sum := sha256.Sum256(blindNonce)
		blindHash = hex.EncodeToString(sum[:])
	}

	claims := scopedTokenClaims{
		Version:    scopedTokenVersion,
		TokenID:    hex.EncodeToString(idBytes),
		BlindHash:  blindHash,
		ExpiresAt:  time.Now().Add(cs.ttl).Unix(),
		Generation: generation,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return ClientCredential{}, err
	}
	scopedToken := base64.StdEncoding.EncodeToString(payloadJSON)
	scopedTokenSigB64, err := cs.signScopedToken(scopedToken, generation)
	if err != nil {
		return ClientCredential{}, err
	}
	clientID := scopedTokenFingerprint(scopedToken, scopedTokenSigB64)

	cred := ClientCredential{
		ClientID:          clientID,
		ScopedToken:       scopedToken,
		ScopedTokenSigB64: scopedTokenSigB64,
		Secret:            append([]byte(nil), secret...),
		ExpiresAt:         time.Unix(claims.ExpiresAt, 0),
		Generation:        generation,
		BlindHash:         blindHash,
	}

	cs.mu.Lock()
	cs.data[cred.ClientID] = cred
	cs.mu.Unlock()

	return cred, nil
}

func (cs *CredentialStore) ValidateScopedToken(
	scopedToken string,
	scopedTokenSigB64 string,
) (ClientCredential, bool) {
	payloadRaw, err := base64.StdEncoding.DecodeString(scopedToken)
	if err != nil {
		return ClientCredential{}, false
	}

	var claims scopedTokenClaims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return ClientCredential{}, false
	}
	if claims.Version != scopedTokenVersion || claims.TokenID == "" || claims.Generation == 0 {
		return ClientCredential{}, false
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return ClientCredential{}, false
	}

	if !cs.generationAllowed(claims.Generation, time.Now()) {
		return ClientCredential{}, false
	}

	signingKey, ok := cs.signingKey(claims.Generation)
	if !ok {
		return ClientCredential{}, false
	}
	expectedSig := computeScopedTokenSignature(signingKey, scopedToken)
	if !verifyHMACB64(scopedTokenSigB64, expectedSig) {
		return ClientCredential{}, false
	}

	clientID := scopedTokenFingerprint(scopedToken, scopedTokenSigB64)
	cred, ok := cs.Get(clientID)
	if !ok {
		return ClientCredential{}, false
	}
	if cred.Generation != claims.Generation {
		return ClientCredential{}, false
	}
	if cred.ExpiresAt.Unix() != claims.ExpiresAt {
		return ClientCredential{}, false
	}
	if claims.BlindHash != cred.BlindHash {
		return ClientCredential{}, false
	}
	return cred, true
}

func (cs *CredentialStore) Get(clientID string) (ClientCredential, bool) {
	cs.mu.RLock()
	cred, ok := cs.data[clientID]
	cs.mu.RUnlock()
	if !ok {
		return ClientCredential{}, false
	}
	if !cred.RevokedAt.IsZero() {
		return ClientCredential{}, false
	}
	if !cred.ExpiresAt.After(time.Now()) {
		cs.Delete(clientID)
		return ClientCredential{}, false
	}
	if !cs.generationAllowed(cred.Generation, time.Now()) {
		return ClientCredential{}, false
	}
	cred.Secret = append([]byte(nil), cred.Secret...)
	return cred, true
}

func (cs *CredentialStore) Delete(clientID string) {
	cs.mu.Lock()
	delete(cs.data, clientID)
	cs.mu.Unlock()
}

func (cs *CredentialStore) ToResponse(cred ClientCredential) RegistrationResponse {
	return RegistrationResponse{
		ScopedToken:       cred.ScopedToken,
		ScopedTokenSigB64: cred.ScopedTokenSigB64,
		TokenSecretB64:    base64.StdEncoding.EncodeToString(cred.Secret),
		TokenFingerprint:  cred.ClientID,
		BlindHash:         cred.BlindHash,
		ExpiresAt:         cred.ExpiresAt.Unix(),
		CredentialVersion: cred.Generation,
		ClientID:          cred.ClientID,
		ClientSecretB64:   base64.StdEncoding.EncodeToString(cred.Secret),
	}
}

// Rotate promotes a new active credential generation and keeps the previous one
// valid for a bounded overlap window so clients can refresh seamlessly.
func (cs *CredentialStore) Rotate(overlap time.Duration) RotationResponse {
	if overlap <= 0 {
		overlap = cs.rotationOverlap
	}
	now := time.Now()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.previousGeneration = cs.activeGeneration
	cs.previousValidUntil = now.Add(overlap)
	cs.activeGeneration++
	cs.signingKeys[cs.activeGeneration] = generateScopedTokenSigningKey()
	return RotationResponse{
		ActiveVersion:   cs.activeGeneration,
		PreviousVersion: cs.previousGeneration,
		OverlapEndsAt:   cs.previousValidUntil.Unix(),
	}
}

// Revoke marks a credential unusable immediately.
func (cs *CredentialStore) Revoke(clientID string) bool {
	now := time.Now()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cred, ok := cs.data[clientID]
	if !ok {
		return false
	}
	cred.RevokedAt = now
	cs.data[clientID] = cred
	return true
}

// Replace issues a fresh credential and revokes the old client id.
func (cs *CredentialStore) Replace(clientID string) (ClientCredential, bool, error) {
	if !cs.Revoke(clientID) {
		return ClientCredential{}, false, nil
	}
	next, err := cs.Issue()
	if err != nil {
		return ClientCredential{}, true, err
	}
	return next, true, nil
}

func (cs *CredentialStore) generationAllowed(generation uint64, now time.Time) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if generation == cs.activeGeneration {
		return true
	}
	if generation == cs.previousGeneration && cs.previousValidUntil.After(now) {
		return true
	}
	return false
}

func (cs *CredentialStore) currentGeneration() uint64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.activeGeneration
}

func (cs *CredentialStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		cs.mu.Lock()
		for id, cred := range cs.data {
			if !cred.ExpiresAt.After(now) {
				delete(cs.data, id)
			}
		}
		for generation := range cs.signingKeys {
			if generation == cs.activeGeneration {
				continue
			}
			if generation == cs.previousGeneration && cs.previousValidUntil.After(now) {
				continue
			}
			delete(cs.signingKeys, generation)
		}
		cs.mu.Unlock()
	}
}

func (cs *CredentialStore) signScopedToken(scopedToken string, generation uint64) (string, error) {
	signingKey, ok := cs.signingKey(generation)
	if !ok {
		return "", errCredentialGenerationUnavailable
	}
	return computeScopedTokenSignature(signingKey, scopedToken), nil
}

func (cs *CredentialStore) signingKey(generation uint64) ([]byte, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	key, ok := cs.signingKeys[generation]
	if !ok || len(key) == 0 {
		return nil, false
	}
	return append([]byte(nil), key...), true
}

func generateScopedTokenSigningKey() []byte {
	key := make([]byte, defaultCredentialSecretSize)
	if _, err := crand.Read(key); err == nil {
		return key
	}
	// Defensive fallback if system RNG fails.
	sum := sha256.Sum256([]byte(time.Now().UTC().String()))
	return append([]byte(nil), sum[:]...)
}

func computeScopedTokenSignature(signingKey []byte, scopedToken string) string {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(scopedToken))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func scopedTokenFingerprint(scopedToken string, scopedTokenSigB64 string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{scopedToken, scopedTokenSigB64}, ".")))
	return hex.EncodeToString(sum[:])
}
