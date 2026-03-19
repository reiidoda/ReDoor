package network

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultClientRPS             = 40
	defaultClientBurst           = 80
	defaultReceiverRPS           = 80
	defaultReceiverBurst         = 120
	defaultSpendUnitWindowSec    = 30
	defaultChallengeDifficulty   = 14
	defaultChallengeWindowSec    = 30
	defaultChallengeQueuePercent = 80
)

type abuseBucketMode string

const (
	bucketModeAnonymousSpendUnit abuseBucketMode = "anonymous_spend_unit"
	bucketModeLegacyClient       abuseBucketMode = "legacy_client"
	bucketModeDualEnforce        abuseBucketMode = "dual_enforce"
)

type AbuseConfig struct {
	ClientRPS               float64
	ClientBurst             float64
	ReceiverRPS             float64
	ReceiverBurst           float64
	IssuerRPS               float64
	IssuerBurst             float64
	SpendUnitWindow         time.Duration
	BucketMode              abuseBucketMode
	ChallengeDifficulty     uint
	ChallengeWindow         time.Duration
	ChallengeQueueThreshold int
}

type AbuseMetricsSnapshot struct {
	RequestsAllowed        uint64 `json:"requests_allowed"`
	Denied                 uint64 `json:"denied"`
	ClientBudgetThrottle   uint64 `json:"client_budget_throttle"`
	SpendUnitThrottle      uint64 `json:"spend_unit_throttle"`
	LegacyBudgetThrottle   uint64 `json:"legacy_budget_throttle"`
	IssuerBudgetThrottle   uint64 `json:"issuer_budget_throttle"`
	ReceiverBudgetThrottle uint64 `json:"receiver_budget_throttle"`
	QueuePressureSignals   uint64 `json:"queue_pressure_signals"`
	ChallengeRequired      uint64 `json:"challenge_required"`
	ChallengePassed        uint64 `json:"challenge_passed"`
	ChallengeFailed        uint64 `json:"challenge_failed"`
}

type AbuseController struct {
	clientLimiter           *RateLimiter
	legacyLimiter           *RateLimiter
	issuerLimiter           *RateLimiter
	receiverLimiter         *RateLimiter
	spendUnitWindow         time.Duration
	bucketMode              abuseBucketMode
	challengeDifficulty     uint
	challengeWindow         time.Duration
	challengeQueueThreshold int

	requestsAllowed        atomic.Uint64
	denied                 atomic.Uint64
	clientBudgetThrottle   atomic.Uint64
	spendUnitThrottle      atomic.Uint64
	legacyBudgetThrottle   atomic.Uint64
	issuerBudgetThrottle   atomic.Uint64
	receiverBudgetThrottle atomic.Uint64
	queuePressureSignals   atomic.Uint64
	challengeRequired      atomic.Uint64
	challengePassed        atomic.Uint64
	challengeFailed        atomic.Uint64
}

func NewAbuseController(cfg AbuseConfig) *AbuseController {
	if cfg.ClientRPS <= 0 {
		cfg.ClientRPS = defaultClientRPS
	}
	if cfg.ClientBurst <= 0 {
		cfg.ClientBurst = defaultClientBurst
	}
	if cfg.ReceiverRPS <= 0 {
		cfg.ReceiverRPS = defaultReceiverRPS
	}
	if cfg.ReceiverBurst <= 0 {
		cfg.ReceiverBurst = defaultReceiverBurst
	}
	if cfg.BucketMode == "" {
		cfg.BucketMode = bucketModeAnonymousSpendUnit
	}
	if cfg.SpendUnitWindow <= 0 {
		cfg.SpendUnitWindow = defaultSpendUnitWindowSec * time.Second
	}
	if cfg.ChallengeWindow <= 0 {
		cfg.ChallengeWindow = defaultChallengeWindowSec * time.Second
	}

	var legacyLimiter *RateLimiter
	if cfg.BucketMode == bucketModeDualEnforce {
		legacyLimiter = NewRateLimiter(cfg.ClientRPS, cfg.ClientBurst)
	}

	var issuerLimiter *RateLimiter
	if cfg.IssuerRPS > 0 && cfg.IssuerBurst > 0 {
		issuerLimiter = NewRateLimiter(cfg.IssuerRPS, cfg.IssuerBurst)
	}

	return &AbuseController{
		clientLimiter:           NewRateLimiter(cfg.ClientRPS, cfg.ClientBurst),
		legacyLimiter:           legacyLimiter,
		issuerLimiter:           issuerLimiter,
		receiverLimiter:         NewRateLimiter(cfg.ReceiverRPS, cfg.ReceiverBurst),
		spendUnitWindow:         cfg.SpendUnitWindow,
		bucketMode:              cfg.BucketMode,
		challengeDifficulty:     cfg.ChallengeDifficulty,
		challengeWindow:         cfg.ChallengeWindow,
		challengeQueueThreshold: cfg.ChallengeQueueThreshold,
	}
}

func NewAbuseControllerFromEnv(maxPending int) *AbuseController {
	clientRPS, clientBurst := ParseRateEnv(
		os.Getenv("RELAY_CLIENT_RPS"),
		os.Getenv("RELAY_CLIENT_BURST"),
		defaultClientRPS,
		defaultClientBurst,
	)
	receiverRPS, receiverBurst := ParseRateEnv(
		os.Getenv("RELAY_RECEIVER_RPS"),
		os.Getenv("RELAY_RECEIVER_BURST"),
		defaultReceiverRPS,
		defaultReceiverBurst,
	)
	issuerRPS, issuerBurst := ParseRateEnv(
		os.Getenv("RELAY_ISSUER_RPS"),
		os.Getenv("RELAY_ISSUER_BURST"),
		0,
		0,
	)
	spendUnitWindowSec := parseIntWithDefault("RELAY_ABUSE_SPEND_UNIT_WINDOW_SEC", defaultSpendUnitWindowSec)
	if spendUnitWindowSec <= 0 {
		spendUnitWindowSec = defaultSpendUnitWindowSec
	}

	challengeDifficulty := uint(parseIntWithDefault("RELAY_CHALLENGE_DIFFICULTY", defaultChallengeDifficulty))
	challengeWindowSec := parseIntWithDefault("RELAY_CHALLENGE_WINDOW_SEC", defaultChallengeWindowSec)
	queueThreshold := parseIntWithDefault("RELAY_CHALLENGE_QUEUE_THRESHOLD", 0)
	if queueThreshold <= 0 && maxPending > 0 {
		queueThreshold = (maxPending * defaultChallengeQueuePercent) / 100
		if queueThreshold <= 0 {
			queueThreshold = 1
		}
	}

	return NewAbuseController(AbuseConfig{
		ClientRPS:               clientRPS,
		ClientBurst:             clientBurst,
		ReceiverRPS:             receiverRPS,
		ReceiverBurst:           receiverBurst,
		IssuerRPS:               issuerRPS,
		IssuerBurst:             issuerBurst,
		SpendUnitWindow:         time.Duration(spendUnitWindowSec) * time.Second,
		BucketMode:              parseAbuseBucketMode(os.Getenv("RELAY_ABUSE_BUCKET_MODE")),
		ChallengeDifficulty:     challengeDifficulty,
		ChallengeWindow:         time.Duration(challengeWindowSec) * time.Second,
		ChallengeQueueThreshold: queueThreshold,
	})
}

func parseIntWithDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func parseAbuseBucketMode(raw string) abuseBucketMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(bucketModeAnonymousSpendUnit):
		return bucketModeAnonymousSpendUnit
	case string(bucketModeLegacyClient):
		return bucketModeLegacyClient
	case string(bucketModeDualEnforce):
		return bucketModeDualEnforce
	default:
		return bucketModeAnonymousSpendUnit
	}
}

func (ac *AbuseController) Snapshot() AbuseMetricsSnapshot {
	if ac == nil {
		return AbuseMetricsSnapshot{}
	}
	return AbuseMetricsSnapshot{
		RequestsAllowed:        ac.requestsAllowed.Load(),
		Denied:                 ac.denied.Load(),
		ClientBudgetThrottle:   ac.clientBudgetThrottle.Load(),
		SpendUnitThrottle:      ac.spendUnitThrottle.Load(),
		LegacyBudgetThrottle:   ac.legacyBudgetThrottle.Load(),
		IssuerBudgetThrottle:   ac.issuerBudgetThrottle.Load(),
		ReceiverBudgetThrottle: ac.receiverBudgetThrottle.Load(),
		QueuePressureSignals:   ac.queuePressureSignals.Load(),
		ChallengeRequired:      ac.challengeRequired.Load(),
		ChallengePassed:        ac.challengePassed.Load(),
		ChallengeFailed:        ac.challengeFailed.Load(),
	}
}

func HandleAbuseMetrics(ac *AbuseController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(ac.Snapshot()); err != nil {
			http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
			return
		}
	}
}

func (ac *AbuseController) enforce(w http.ResponseWriter, r *http.Request, receiver string, pendingCount int) bool {
	if ac == nil {
		return true
	}

	keys := resolveAbuseKeys(r, time.Now(), ac.spendUnitWindow)
	clientKey := keys.legacy
	if ac.bucketMode != bucketModeLegacyClient {
		clientKey = keys.spendUnit
	}

	clientOver := ac.clientLimiter != nil && !ac.clientLimiter.AllowKey(clientKey)
	legacyOver := ac.bucketMode == bucketModeDualEnforce &&
		ac.legacyLimiter != nil &&
		!ac.legacyLimiter.AllowKey(keys.legacy)
	issuerOver := ac.issuerLimiter != nil && keys.issuer != "" && !ac.issuerLimiter.AllowKey(keys.issuer)
	receiverOver := receiver != "" && ac.receiverLimiter != nil && !ac.receiverLimiter.AllowKey(receiver)
	queuePressure := receiver != "" &&
		ac.challengeQueueThreshold > 0 &&
		pendingCount >= ac.challengeQueueThreshold

	if !clientOver && !legacyOver && !issuerOver && !receiverOver && !queuePressure {
		ac.requestsAllowed.Add(1)
		return true
	}

	reasons := make([]string, 0, 5)
	if clientOver {
		ac.clientBudgetThrottle.Add(1)
		if ac.bucketMode == bucketModeLegacyClient {
			reasons = append(reasons, "client_budget")
		} else {
			ac.spendUnitThrottle.Add(1)
			reasons = append(reasons, "spend_unit_budget")
		}
	}
	if legacyOver {
		ac.legacyBudgetThrottle.Add(1)
		reasons = append(reasons, "legacy_budget")
	}
	if issuerOver {
		ac.issuerBudgetThrottle.Add(1)
		reasons = append(reasons, "issuer_budget")
	}
	if receiverOver {
		ac.receiverBudgetThrottle.Add(1)
		reasons = append(reasons, "receiver_budget")
	}
	if queuePressure {
		ac.queuePressureSignals.Add(1)
		reasons = append(reasons, "queue_pressure")
	}

	if ac.challengeDifficulty == 0 {
		ac.denied.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Abuse budget exceeded", http.StatusTooManyRequests)
		return false
	}

	ac.challengeRequired.Add(1)
	if ac.verifyChallenge(r, clientKey, receiver) {
		ac.challengePassed.Add(1)
		ac.requestsAllowed.Add(1)
		return true
	}

	ac.challengeFailed.Add(1)
	ac.denied.Add(1)
	w.Header().Set("Retry-After", "1")
	w.Header().Set("X-Abuse-Challenge-Difficulty", fmt.Sprintf("%d", ac.challengeDifficulty))
	w.Header().Set("X-Abuse-Challenge-Window-Sec", fmt.Sprintf("%d", int(ac.challengeWindow.Seconds())))
	w.Header().Set("X-Abuse-Challenge-Reasons", strings.Join(reasons, ","))
	http.Error(w, "Challenge required", http.StatusTooManyRequests)
	return false
}

type abuseRequestKeys struct {
	legacy    string
	spendUnit string
	issuer    string
}

func scopedClientKey(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-Scoped-Token")); token != "" {
		if tokenSig := strings.TrimSpace(r.Header.Get("X-Scoped-Token-Signature")); tokenSig != "" {
			return "token:" + scopedTokenFingerprint(token, tokenSig)
		}
	}
	if scoped := strings.TrimSpace(r.Header.Get("X-Client-ID")); scoped != "" {
		return "client:" + scoped
	}
	return "ip:" + clientIP(r)
}

func resolveAbuseKeys(r *http.Request, now time.Time, spendUnitWindow time.Duration) abuseRequestKeys {
	legacy := scopedClientKey(r)
	slotSec := int64(spendUnitWindow.Seconds())
	if slotSec <= 0 {
		slotSec = defaultSpendUnitWindowSec
	}
	slot := now.Unix() / slotSec

	if token := strings.TrimSpace(r.Header.Get("X-Scoped-Token")); token != "" {
		tokenSig := strings.TrimSpace(r.Header.Get("X-Scoped-Token-Signature"))
		fingerprint := scopedTokenFingerprint(token, tokenSig)
		generation := scopedTokenGeneration(token)
		return abuseRequestKeys{
			legacy: legacy,
			spendUnit: "su:" + anonymizeBucketKey(
				"token",
				fingerprint,
				strconv.FormatInt(slot, 10),
				strconv.FormatUint(generation, 10),
			),
			issuer: scopedTokenIssuerKey(generation, tokenSig),
		}
	}

	return abuseRequestKeys{
		legacy: legacy,
		spendUnit: "su:" + anonymizeBucketKey(
			legacy,
			strconv.FormatInt(slot, 10),
		),
	}
}

func anonymizeBucketKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

func scopedTokenGeneration(scopedToken string) uint64 {
	raw, err := base64.StdEncoding.DecodeString(scopedToken)
	if err != nil {
		return 0
	}
	var claims struct {
		Generation uint64 `json:"gen"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return 0
	}
	return claims.Generation
}

func scopedTokenIssuerKey(generation uint64, scopedTokenSig string) string {
	if generation > 0 {
		return fmt.Sprintf("issuer:generation:%d", generation)
	}
	if scopedTokenSig != "" {
		return "issuer:sig:" + anonymizeBucketKey(scopedTokenSig)
	}
	return ""
}

func (ac *AbuseController) verifyChallenge(r *http.Request, clientKey, receiver string) bool {
	tsHeader := strings.TrimSpace(r.Header.Get("X-Abuse-Challenge-Timestamp"))
	solution := strings.TrimSpace(r.Header.Get("X-Abuse-Challenge-Solution"))
	if tsHeader == "" || solution == "" {
		return false
	}
	tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	windowSec := int64(ac.challengeWindow.Seconds())
	if windowSec <= 0 {
		windowSec = defaultChallengeWindowSec
	}
	if delta := now - tsUnix; delta > windowSec || delta < -windowSec {
		return false
	}

	canonical := strings.Join([]string{
		clientKey,
		receiver,
		strings.ToUpper(r.Method),
		r.URL.Path,
		tsHeader,
		solution,
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	return hasLeadingZeroBits(sum[:], ac.challengeDifficulty)
}

func hasLeadingZeroBits(data []byte, bits uint) bool {
	remaining := bits
	for _, b := range data {
		if remaining == 0 {
			return true
		}
		if remaining >= 8 {
			if b != 0 {
				return false
			}
			remaining -= 8
			continue
		}
		mask := byte(0xFF << (8 - remaining))
		return (b & mask) == 0
	}
	return remaining == 0
}
