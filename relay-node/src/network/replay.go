package network

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultHMACMaxSkew = 5 * time.Minute
	defaultNonceTTL    = 10 * time.Minute
)

var (
	errMissingTimestamp = errors.New("missing X-HMAC-Timestamp header")
	errMissingNonce     = errors.New("missing X-HMAC-Nonce header")
	errInvalidTimestamp = errors.New("invalid X-HMAC-Timestamp header")
	errStaleTimestamp   = errors.New("stale X-HMAC timestamp")
	errReplayNonce      = errors.New("replayed X-HMAC nonce")
)

type replayProtector struct {
	nowFunc   func() time.Time
	maxSkew   time.Duration
	nonceTTL  time.Duration
	mu        sync.Mutex
	nonceSeen map[string]time.Time
}

func newReplayProtectorFromEnv() *replayProtector {
	maxSkew := parseDurationSecondsEnv("RELAY_HMAC_MAX_SKEW_SEC", defaultHMACMaxSkew)
	nonceTTL := parseDurationSecondsEnv("RELAY_HMAC_NONCE_TTL_SEC", defaultNonceTTL)
	if nonceTTL < maxSkew {
		nonceTTL = maxSkew
	}
	return &replayProtector{
		nowFunc:   time.Now,
		maxSkew:   maxSkew,
		nonceTTL:  nonceTTL,
		nonceSeen: make(map[string]time.Time),
	}
}

func (rp *replayProtector) validateWithScope(scope, timestampHeader, nonceHeader string) error {
	if timestampHeader == "" {
		return errMissingTimestamp
	}
	if nonceHeader == "" {
		return errMissingNonce
	}

	tsSec, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return errInvalidTimestamp
	}

	now := rp.nowFunc()
	ts := time.Unix(tsSec, 0)
	if now.Sub(ts) > rp.maxSkew || ts.Sub(now) > rp.maxSkew {
		return errStaleTimestamp
	}

	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.pruneLocked(now)
	nonceKey := nonceHeader
	if scope != "" {
		nonceKey = scope + ":" + nonceHeader
	}
	if expiry, exists := rp.nonceSeen[nonceKey]; exists && expiry.After(now) {
		return errReplayNonce
	}
	rp.nonceSeen[nonceKey] = now.Add(rp.nonceTTL)
	return nil
}

func (rp *replayProtector) pruneLocked(now time.Time) {
	for nonce, expiry := range rp.nonceSeen {
		if !expiry.After(now) {
			delete(rp.nonceSeen, nonce)
		}
	}
}

func parseDurationSecondsEnv(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 {
		return def
	}
	return time.Duration(secs) * time.Second
}

func statusForReplayError(err error) (int, string) {
	switch err {
	case errMissingTimestamp, errMissingNonce, errInvalidTimestamp:
		return 400, err.Error()
	case errStaleTimestamp, errReplayNonce:
		return 401, err.Error()
	default:
		return 401, fmt.Sprintf("unauthorized: %v", err)
	}
}
