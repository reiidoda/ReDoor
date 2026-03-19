package onion

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultChaffIntervalFloor  = 1500 * time.Millisecond
	defaultChaffIntervalCeil   = 3500 * time.Millisecond
	defaultChaffPayloadMin     = 96
	defaultChaffPayloadMax     = 320
	defaultChaffBudgetPerMin   = 120
	defaultChaffPathMinHops    = 2
	defaultChaffPathMaxHops    = 3
	defaultChaffForwardTimeout = 8 * time.Second
)

// RelayMixPeer configures a relay URL + X25519 public key.
type RelayMixPeer struct {
	URL       string `json:"url"`
	PublicKey []byte `json:"public_key"`
}

// RelayChaffConfig controls relay-generated mix chaff behavior.
type RelayChaffConfig struct {
	Enabled        bool
	IntervalMin    time.Duration
	IntervalMax    time.Duration
	PayloadMin     int
	PayloadMax     int
	PathMinHops    int
	PathMaxHops    int
	BudgetPerMin   int
	ForwardTimeout time.Duration
}

// RelayChaffMetrics reports relay-generated chaff behavior and safety budget outcomes.
type RelayChaffMetrics struct {
	Enabled          bool   `json:"enabled"`
	PeerCount        int    `json:"peer_count"`
	IntervalMinMS    uint64 `json:"interval_min_ms"`
	IntervalMaxMS    uint64 `json:"interval_max_ms"`
	PayloadMinBytes  int    `json:"payload_min_bytes"`
	PayloadMaxBytes  int    `json:"payload_max_bytes"`
	PathMinHops      int    `json:"path_min_hops"`
	PathMaxHops      int    `json:"path_max_hops"`
	BudgetPerMin     int    `json:"budget_per_min"`
	Generated        uint64 `json:"generated"`
	Forwarded        uint64 `json:"forwarded"`
	ForwardFailures  uint64 `json:"forward_failures"`
	BuildFailures    uint64 `json:"build_failures"`
	BudgetThrottled  uint64 `json:"budget_throttled"`
	LastEmitUnixMS   uint64 `json:"last_emit_unix_ms"`
	LastError        string `json:"last_error,omitempty"`
	LastForwardedURL string `json:"last_forwarded_url,omitempty"`
}

type relayChaffStats struct {
	generated       uint64
	forwarded       uint64
	forwardFailures uint64
	buildFailures   uint64
	budgetThrottled uint64
	lastEmitUnixMS  uint64
	lastError       string
	lastForwarded   string
}

// RelayChaffGenerator emits relay-originated chaff through the mix pipeline.
// Chaff generation is bounded by a local token budget to avoid self-induced DoS.
type RelayChaffGenerator struct {
	cfg    RelayChaffConfig
	peers  []RelayMixPeer
	sendFn func(targetURL, msgID string, packet []byte) error

	stopCh chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	mu         sync.Mutex
	stats      relayChaffStats
	budget     float64
	lastRefill time.Time
}

// NewRelayChaffGenerator creates a generator with explicit config and peer set.
func NewRelayChaffGenerator(
	cfg RelayChaffConfig,
	peers []RelayMixPeer,
	sendFn func(targetURL, msgID string, packet []byte) error,
) *RelayChaffGenerator {
	cfg = normalizeRelayChaffConfig(cfg, len(peers))
	copiedPeers := make([]RelayMixPeer, 0, len(peers))
	for _, p := range peers {
		if strings.TrimSpace(p.URL) == "" || len(p.PublicKey) != 32 {
			continue
		}
		pub := append([]byte(nil), p.PublicKey...)
		copiedPeers = append(copiedPeers, RelayMixPeer{
			URL:       strings.TrimSpace(p.URL),
			PublicKey: pub,
		})
	}

	if sendFn == nil {
		sendFn = func(targetURL, msgID string, packet []byte) error {
			return ForwardSphinxPacket(targetURL, msgID, packet)
		}
	}

	g := &RelayChaffGenerator{
		cfg:        cfg,
		peers:      copiedPeers,
		sendFn:     sendFn,
		stopCh:     make(chan struct{}),
		budget:     float64(cfg.BudgetPerMin),
		lastRefill: time.Now(),
	}
	if len(copiedPeers) == 0 {
		g.cfg.Enabled = false
	}
	return g
}

// NewRelayChaffGeneratorFromEnv configures relay chaff generation from env.
func NewRelayChaffGeneratorFromEnv(forwarder *MixForwarder) *RelayChaffGenerator {
	cfg := RelayChaffConfig{
		Enabled:        strings.TrimSpace(os.Getenv("RELAY_CHAFF_ENABLED")) == "1",
		IntervalMin:    parseMillisEnv("RELAY_CHAFF_INTERVAL_MIN_MS", defaultChaffIntervalFloor),
		IntervalMax:    parseMillisEnv("RELAY_CHAFF_INTERVAL_MAX_MS", defaultChaffIntervalCeil),
		PayloadMin:     parsePositiveIntEnv("RELAY_CHAFF_PAYLOAD_MIN_BYTES", defaultChaffPayloadMin),
		PayloadMax:     parsePositiveIntEnv("RELAY_CHAFF_PAYLOAD_MAX_BYTES", defaultChaffPayloadMax),
		PathMinHops:    parsePositiveIntEnv("RELAY_CHAFF_PATH_MIN_HOPS", defaultChaffPathMinHops),
		PathMaxHops:    parsePositiveIntEnv("RELAY_CHAFF_PATH_MAX_HOPS", defaultChaffPathMaxHops),
		BudgetPerMin:   parsePositiveIntEnv("RELAY_CHAFF_BUDGET_PER_MIN", defaultChaffBudgetPerMin),
		ForwardTimeout: parseMillisEnv("RELAY_CHAFF_FORWARD_TIMEOUT_MS", defaultChaffForwardTimeout),
	}

	peers, err := parseRelayChaffPeersEnv(os.Getenv("RELAY_CHAFF_PEERS"))
	if err != nil {
		// Keep generator disabled but expose reason via metrics.
		g := NewRelayChaffGenerator(cfg, nil, nil)
		g.mu.Lock()
		g.stats.lastError = fmt.Sprintf("invalid RELAY_CHAFF_PEERS: %v", err)
		g.mu.Unlock()
		return g
	}

	sendFn := func(targetURL, msgID string, packet []byte) error {
		if forwarder != nil {
			return forwarder.Forward(targetURL, msgID, packet)
		}
		return ForwardSphinxPacket(targetURL, msgID, packet)
	}
	return NewRelayChaffGenerator(cfg, peers, sendFn)
}

// Start begins periodic relay-generated chaff emission.
func (g *RelayChaffGenerator) Start() {
	if g == nil || !g.cfg.Enabled || len(g.peers) == 0 {
		return
	}
	g.wg.Add(1)
	go g.run()
}

// Close stops background chaff generation.
func (g *RelayChaffGenerator) Close() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		close(g.stopCh)
		g.wg.Wait()
	})
}

// Enabled returns whether generator policy allows emissions.
func (g *RelayChaffGenerator) Enabled() bool {
	if g == nil {
		return false
	}
	return g.cfg.Enabled && len(g.peers) > 0
}

// MetricsSnapshot returns current relay-chaff runtime metrics.
func (g *RelayChaffGenerator) MetricsSnapshot() RelayChaffMetrics {
	if g == nil {
		return RelayChaffMetrics{}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	return RelayChaffMetrics{
		Enabled:          g.cfg.Enabled && len(g.peers) > 0,
		PeerCount:        len(g.peers),
		IntervalMinMS:    uint64(g.cfg.IntervalMin / time.Millisecond),
		IntervalMaxMS:    uint64(g.cfg.IntervalMax / time.Millisecond),
		PayloadMinBytes:  g.cfg.PayloadMin,
		PayloadMaxBytes:  g.cfg.PayloadMax,
		PathMinHops:      g.cfg.PathMinHops,
		PathMaxHops:      g.cfg.PathMaxHops,
		BudgetPerMin:     g.cfg.BudgetPerMin,
		Generated:        g.stats.generated,
		Forwarded:        g.stats.forwarded,
		ForwardFailures:  g.stats.forwardFailures,
		BuildFailures:    g.stats.buildFailures,
		BudgetThrottled:  g.stats.budgetThrottled,
		LastEmitUnixMS:   g.stats.lastEmitUnixMS,
		LastError:        g.stats.lastError,
		LastForwardedURL: g.stats.lastForwarded,
	}
}

func (g *RelayChaffGenerator) run() {
	defer g.wg.Done()
	for {
		sleep := g.nextInterval()
		timer := time.NewTimer(sleep)
		select {
		case <-g.stopCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}

		g.runOnce()
	}
}

func (g *RelayChaffGenerator) runOnce() {
	if !g.consumeBudgetToken(time.Now()) {
		g.mu.Lock()
		g.stats.budgetThrottled++
		g.mu.Unlock()
		return
	}

	entryURL, msgID, packet, err := g.buildChaffPacket()
	if err != nil {
		g.mu.Lock()
		g.stats.buildFailures++
		g.stats.lastError = err.Error()
		g.mu.Unlock()
		return
	}

	g.mu.Lock()
	g.stats.generated++
	g.mu.Unlock()

	if err := g.forwardWithTimeout(entryURL, msgID, packet); err != nil {
		g.mu.Lock()
		g.stats.forwardFailures++
		g.stats.lastError = err.Error()
		g.mu.Unlock()
		return
	}

	g.mu.Lock()
	g.stats.forwarded++
	g.stats.lastForwarded = entryURL
	g.stats.lastEmitUnixMS = uint64(time.Now().UnixMilli())
	g.stats.lastError = ""
	g.mu.Unlock()
}

func (g *RelayChaffGenerator) forwardWithTimeout(targetURL, msgID string, packet []byte) error {
	if g.cfg.ForwardTimeout <= 0 {
		return g.sendFn(targetURL, msgID, packet)
	}

	result := make(chan error, 1)
	go func() {
		result <- g.sendFn(targetURL, msgID, packet)
	}()

	select {
	case err := <-result:
		return err
	case <-time.After(g.cfg.ForwardTimeout):
		return fmt.Errorf("relay chaff forward timeout after %s", g.cfg.ForwardTimeout)
	}
}

func (g *RelayChaffGenerator) nextInterval() time.Duration {
	intervalFloor := g.cfg.IntervalMin
	intervalCeil := g.cfg.IntervalMax
	if intervalCeil <= intervalFloor {
		return intervalFloor
	}
	delta := intervalCeil - intervalFloor
	return intervalFloor + time.Duration(mrand.Int63n(int64(delta)+1))
}

func (g *RelayChaffGenerator) consumeBudgetToken(now time.Time) bool {
	if g.cfg.BudgetPerMin <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	elapsedSec := now.Sub(g.lastRefill).Seconds()
	g.lastRefill = now
	refill := elapsedSec * (float64(g.cfg.BudgetPerMin) / 60.0)
	g.budget += refill
	maxBudget := float64(g.cfg.BudgetPerMin)
	if g.budget > maxBudget {
		g.budget = maxBudget
	}
	if g.budget < 1.0 {
		return false
	}
	g.budget -= 1.0
	return true
}

func (g *RelayChaffGenerator) buildChaffPacket() (string, string, []byte, error) {
	hops := g.pickHopCount()
	if hops <= 0 || hops > len(g.peers) {
		return "", "", nil, fmt.Errorf("invalid chaff hop count")
	}

	selected := pickUniquePeers(g.peers, hops)
	if len(selected) == 0 {
		return "", "", nil, fmt.Errorf("no chaff peers selected")
	}

	payload := make([]byte, randomIntRange(g.cfg.PayloadMin, g.cfg.PayloadMax))
	if _, err := rand.Read(payload); err != nil {
		return "", "", nil, fmt.Errorf("generate chaff payload: %w", err)
	}

	finalLayer := hopPayload{
		V:             1,
		Mode:          "final",
		FinalReceiver: "__cover__",
		Payload:       payload,
	}
	finalBytes, err := json.Marshal(finalLayer)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal final chaff layer: %w", err)
	}

	current, err := encryptPacket(selected[len(selected)-1].PublicKey, finalBytes)
	if err != nil {
		return "", "", nil, fmt.Errorf("encrypt final chaff layer: %w", err)
	}

	for i := len(selected) - 2; i >= 0; i-- {
		next := selected[i+1]
		route := hopPayload{
			V:             1,
			Mode:          "route",
			NextHop:       next.URL,
			NextHopPubKey: hex.EncodeToString(next.PublicKey),
			Payload:       current,
		}
		routeBytes, err := json.Marshal(route)
		if err != nil {
			return "", "", nil, fmt.Errorf("marshal route chaff layer: %w", err)
		}
		current, err = encryptPacket(selected[i].PublicKey, routeBytes)
		if err != nil {
			return "", "", nil, fmt.Errorf("encrypt route chaff layer: %w", err)
		}
	}

	return selected[0].URL, randomMessageID(), current, nil
}

func (g *RelayChaffGenerator) pickHopCount() int {
	if len(g.peers) == 0 {
		return 0
	}
	hopMin := g.cfg.PathMinHops
	hopMax := g.cfg.PathMaxHops
	if hopMin < 1 {
		hopMin = 1
	}
	if hopMax < hopMin {
		hopMax = hopMin
	}
	if hopMax > len(g.peers) {
		hopMax = len(g.peers)
	}
	if hopMin > hopMax {
		hopMin = hopMax
	}
	return randomIntRange(hopMin, hopMax)
}

func pickUniquePeers(peers []RelayMixPeer, count int) []RelayMixPeer {
	if count <= 0 || len(peers) == 0 {
		return nil
	}
	if count >= len(peers) {
		out := make([]RelayMixPeer, len(peers))
		copy(out, peers)
		shufflePeers(out)
		return out
	}

	indices := make([]int, len(peers))
	for i := range peers {
		indices[i] = i
	}
	for i := len(indices) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}

	out := make([]RelayMixPeer, 0, count)
	for _, idx := range indices[:count] {
		out = append(out, peers[idx])
	}
	return out
}

func shufflePeers(peers []RelayMixPeer) {
	for i := len(peers) - 1; i > 0; i-- {
		j := mrand.Intn(i + 1)
		peers[i], peers[j] = peers[j], peers[i]
	}
}

func randomIntRange(rangeStart, rangeEnd int) int {
	if rangeEnd <= rangeStart {
		return rangeStart
	}
	return rangeStart + mrand.Intn(rangeEnd-rangeStart+1)
}

func parseRelayChaffPeersEnv(raw string) ([]RelayMixPeer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	if strings.HasPrefix(raw, "[") {
		type jsonPeer struct {
			URL    string `json:"url"`
			PubKey string `json:"pub_key"`
		}
		var input []jsonPeer
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			return nil, err
		}
		peers := make([]RelayMixPeer, 0, len(input))
		for _, p := range input {
			peer, err := parseRelayPeerPair(p.URL, p.PubKey)
			if err != nil {
				return nil, err
			}
			peers = append(peers, peer)
		}
		return dedupePeers(peers), nil
	}

	parts := strings.Split(raw, ",")
	peers := make([]RelayMixPeer, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var split []string
		if strings.Contains(part, "|") {
			split = strings.SplitN(part, "|", 2)
		} else {
			split = strings.SplitN(part, "=", 2)
		}
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid peer entry %q", part)
		}
		peer, err := parseRelayPeerPair(split[0], split[1])
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return dedupePeers(peers), nil
}

func parseRelayPeerPair(urlRaw, pubHexRaw string) (RelayMixPeer, error) {
	url := strings.TrimSpace(urlRaw)
	pubHex := strings.TrimSpace(pubHexRaw)
	if url == "" || pubHex == "" {
		return RelayMixPeer{}, fmt.Errorf("empty relay peer url/pub key")
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return RelayMixPeer{}, fmt.Errorf("invalid relay peer pub key: %w", err)
	}
	if len(pub) != 32 {
		return RelayMixPeer{}, fmt.Errorf("relay peer pub key must be 32 bytes")
	}
	return RelayMixPeer{URL: url, PublicKey: pub}, nil
}

func dedupePeers(input []RelayMixPeer) []RelayMixPeer {
	seen := make(map[string]struct{}, len(input))
	out := make([]RelayMixPeer, 0, len(input))
	for _, peer := range input {
		key := strings.TrimSpace(peer.URL)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pub := append([]byte(nil), peer.PublicKey...)
		out = append(out, RelayMixPeer{
			URL:       key,
			PublicKey: pub,
		})
	}
	return out
}

func normalizeRelayChaffConfig(cfg RelayChaffConfig, peerCount int) RelayChaffConfig {
	if cfg.IntervalMin <= 0 {
		cfg.IntervalMin = defaultChaffIntervalFloor
	}
	if cfg.IntervalMax < cfg.IntervalMin {
		cfg.IntervalMax = cfg.IntervalMin
	}

	if cfg.PayloadMin <= 0 {
		cfg.PayloadMin = defaultChaffPayloadMin
	}
	if cfg.PayloadMax < cfg.PayloadMin {
		cfg.PayloadMax = cfg.PayloadMin
	}

	if cfg.PathMinHops <= 0 {
		cfg.PathMinHops = defaultChaffPathMinHops
	}
	if cfg.PathMaxHops < cfg.PathMinHops {
		cfg.PathMaxHops = cfg.PathMinHops
	}
	if peerCount > 0 {
		if cfg.PathMaxHops > peerCount {
			cfg.PathMaxHops = peerCount
		}
		if cfg.PathMinHops > cfg.PathMaxHops {
			cfg.PathMinHops = cfg.PathMaxHops
		}
	}

	if cfg.BudgetPerMin <= 0 {
		cfg.BudgetPerMin = defaultChaffBudgetPerMin
	}
	if cfg.ForwardTimeout <= 0 {
		cfg.ForwardTimeout = defaultChaffForwardTimeout
	}
	return cfg
}

func parsePositiveIntEnv(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
