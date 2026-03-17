package network

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultAnomalyWindowSec      = 60
	defaultAnomalyRateMultiplier = 3.0
	defaultReplaySpikeThreshold  = 20
	defaultMalformedThreshold    = 25
	defaultCredentialThreshold   = 30
)

type detectorConfig struct {
	Threshold      uint64
	RateMultiplier float64
}

type detectorState struct {
	windowStart      time.Time
	count            uint64
	previousCount    uint64
	alerts           uint64
	lastAlertAtUnix  int64
	lastAlertCount   uint64
	lastAlertReason  string
	alertedWindowTag int64
}

type detectorSnapshot struct {
	CurrentWindowCount  uint64  `json:"current_window_count"`
	PreviousWindowCount uint64  `json:"previous_window_count"`
	Threshold           uint64  `json:"threshold"`
	RateMultiplier      float64 `json:"rate_multiplier"`
	Alerts              uint64  `json:"alerts"`
	LastAlertAtUnix     int64   `json:"last_alert_at_unix"`
	LastAlertCount      uint64  `json:"last_alert_count"`
	LastAlertReason     string  `json:"last_alert_reason"`
}

type AnomalySnapshot struct {
	WindowSec       int64             `json:"window_sec"`
	GeneratedAtUnix int64             `json:"generated_at_unix"`
	ReplaySpike     detectorSnapshot  `json:"replay_spike"`
	MalformedBurst  detectorSnapshot  `json:"malformed_burst"`
	CredentialSpray detectorSnapshot  `json:"credential_spray"`
	ActionMap       map[string]string `json:"action_map"`
}

type AnomalyController struct {
	window        time.Duration
	replayCfg     detectorConfig
	malformedCfg  detectorConfig
	credentialCfg detectorConfig

	mu         sync.Mutex
	replay     detectorState
	malformed  detectorState
	credential detectorState
}

var (
	anomalyMu      sync.RWMutex
	currentAnomaly *AnomalyController
)

func NewAnomalyControllerFromEnv() *AnomalyController {
	windowSec := parseIntWithFallback("RELAY_ANOMALY_WINDOW_SEC", defaultAnomalyWindowSec)
	if windowSec <= 0 {
		windowSec = defaultAnomalyWindowSec
	}
	rateMul := parseFloatWithFallback("RELAY_ANOMALY_RATE_MULTIPLIER", defaultAnomalyRateMultiplier)
	if rateMul < 1.0 {
		rateMul = defaultAnomalyRateMultiplier
	}

	return NewAnomalyController(
		time.Duration(windowSec)*time.Second,
		detectorConfig{Threshold: uint64(parseIntWithFallback("RELAY_REPLAY_SPIKE_THRESHOLD", defaultReplaySpikeThreshold)), RateMultiplier: rateMul},
		detectorConfig{Threshold: uint64(parseIntWithFallback("RELAY_MALFORMED_BURST_THRESHOLD", defaultMalformedThreshold)), RateMultiplier: rateMul},
		detectorConfig{Threshold: uint64(parseIntWithFallback("RELAY_CREDENTIAL_SPRAY_THRESHOLD", defaultCredentialThreshold)), RateMultiplier: rateMul},
	)
}

func NewAnomalyController(window time.Duration, replayCfg, malformedCfg, credentialCfg detectorConfig) *AnomalyController {
	if window <= 0 {
		window = defaultAnomalyWindowSec * time.Second
	}
	if replayCfg.Threshold == 0 {
		replayCfg.Threshold = defaultReplaySpikeThreshold
	}
	if malformedCfg.Threshold == 0 {
		malformedCfg.Threshold = defaultMalformedThreshold
	}
	if credentialCfg.Threshold == 0 {
		credentialCfg.Threshold = defaultCredentialThreshold
	}
	if replayCfg.RateMultiplier < 1.0 {
		replayCfg.RateMultiplier = defaultAnomalyRateMultiplier
	}
	if malformedCfg.RateMultiplier < 1.0 {
		malformedCfg.RateMultiplier = defaultAnomalyRateMultiplier
	}
	if credentialCfg.RateMultiplier < 1.0 {
		credentialCfg.RateMultiplier = defaultAnomalyRateMultiplier
	}

	return &AnomalyController{
		window:        window,
		replayCfg:     replayCfg,
		malformedCfg:  malformedCfg,
		credentialCfg: credentialCfg,
	}
}

func SetAnomalyController(ac *AnomalyController) {
	anomalyMu.Lock()
	currentAnomaly = ac
	anomalyMu.Unlock()
}

func getAnomalyController() *AnomalyController {
	anomalyMu.RLock()
	defer anomalyMu.RUnlock()
	return currentAnomaly
}

func RecordReplaySignal() {
	if ac := getAnomalyController(); ac != nil {
		ac.observeReplay(time.Now())
	}
}

func RecordMalformedSignal() {
	if ac := getAnomalyController(); ac != nil {
		ac.observeMalformed(time.Now())
	}
}

func RecordCredentialSpraySignal() {
	if ac := getAnomalyController(); ac != nil {
		ac.observeCredential(time.Now())
	}
}

func (ac *AnomalyController) observeReplay(now time.Time) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.observeDetector(&ac.replay, ac.replayCfg, now)
}

func (ac *AnomalyController) observeMalformed(now time.Time) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.observeDetector(&ac.malformed, ac.malformedCfg, now)
}

func (ac *AnomalyController) observeCredential(now time.Time) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.observeDetector(&ac.credential, ac.credentialCfg, now)
}

func (ac *AnomalyController) observeDetector(st *detectorState, cfg detectorConfig, now time.Time) {
	ac.rotateWindow(st, now)
	st.count++
	windowTag := st.windowStart.Unix()
	if st.alertedWindowTag == windowTag {
		return
	}

	rateTriggered := st.previousCount > 0 && float64(st.count) >= float64(st.previousCount)*cfg.RateMultiplier
	thresholdTriggered := st.count >= cfg.Threshold
	if !rateTriggered && !thresholdTriggered {
		return
	}

	st.alerts++
	st.lastAlertAtUnix = now.Unix()
	st.lastAlertCount = st.count
	if thresholdTriggered {
		st.lastAlertReason = "threshold"
	} else {
		st.lastAlertReason = "rate_of_change"
	}
	st.alertedWindowTag = windowTag
}

func (ac *AnomalyController) rotateWindow(st *detectorState, now time.Time) {
	if st.windowStart.IsZero() {
		st.windowStart = now.Truncate(ac.window)
		return
	}
	if now.Sub(st.windowStart) < ac.window {
		return
	}
	steps := int64(now.Sub(st.windowStart) / ac.window)
	if steps >= 1 {
		st.previousCount = st.count
		if steps > 1 {
			st.previousCount = 0
		}
		st.count = 0
		st.windowStart = st.windowStart.Add(time.Duration(steps) * ac.window)
	}
}

func (ac *AnomalyController) Snapshot() AnomalySnapshot {
	if ac == nil {
		return AnomalySnapshot{}
	}

	ac.mu.Lock()
	now := time.Now()
	ac.rotateWindow(&ac.replay, now)
	ac.rotateWindow(&ac.malformed, now)
	ac.rotateWindow(&ac.credential, now)
	snapshot := AnomalySnapshot{
		WindowSec:       ac.window.Milliseconds() / 1000,
		GeneratedAtUnix: now.Unix(),
		ReplaySpike:     toDetectorSnapshot(ac.replay, ac.replayCfg),
		MalformedBurst:  toDetectorSnapshot(ac.malformed, ac.malformedCfg),
		CredentialSpray: toDetectorSnapshot(ac.credential, ac.credentialCfg),
		ActionMap: map[string]string{
			"relay_replay_spike":     "runbook:section-3-a2-scoped-credential-rotation",
			"relay_malformed_burst":  "runbook:section-2-immediate-triage",
			"relay_credential_spray": "runbook:section-3-a2-scoped-credential-rotation",
		},
	}
	ac.mu.Unlock()

	return snapshot
}

func toDetectorSnapshot(st detectorState, cfg detectorConfig) detectorSnapshot {
	return detectorSnapshot{
		CurrentWindowCount:  st.count,
		PreviousWindowCount: st.previousCount,
		Threshold:           cfg.Threshold,
		RateMultiplier:      cfg.RateMultiplier,
		Alerts:              st.alerts,
		LastAlertAtUnix:     st.lastAlertAtUnix,
		LastAlertCount:      st.lastAlertCount,
		LastAlertReason:     st.lastAlertReason,
	}
}

func HandleAnomalyMetrics(ac *AnomalyController) http.HandlerFunc {
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

func parseIntWithFallback(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseFloatWithFallback(key string, fallback float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
