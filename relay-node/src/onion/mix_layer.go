package onion

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"math"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mixPacketMagic      = "MXP1"
	mixPacketTagLen     = 16
	mixPacketHeaderLen  = 4 + mixPacketTagLen + 32 + 12
	defaultReplayTTL    = 10 * time.Minute
	defaultReplayMaxTag = 50000

	defaultMixBatchMax           = 16
	defaultMixBatchQueueCapacity = 1024
	defaultMixForwardTimeout     = 12 * time.Second
	defaultLegacyMixForwardDelay = 10 * time.Millisecond
)

var (
	// ErrNotMixPacket indicates the payload is not a valid mix packet.
	ErrNotMixPacket = errors.New("not a mix packet")
	// ErrReplayTag indicates packet tag replay at this hop.
	ErrReplayTag = errors.New("replayed mix packet tag")
	// ErrMixForwardQueueFull indicates batching queue is saturated.
	ErrMixForwardQueueFull = errors.New("mix forward queue full")
)

type hopPayload struct {
	V             uint8  `json:"v"`
	Mode          string `json:"mode"`
	NextHop       string `json:"next_hop,omitempty"`
	NextHopPubKey string `json:"next_hop_pub_key,omitempty"`
	FinalReceiver string `json:"final_receiver,omitempty"`
	Payload       []byte `json:"payload"`
}

// ProcessResult is the action produced by one mix processing step.
type ProcessResult struct {
	Forwarded  bool
	Final      bool
	NextHop    string
	ReceiverID string
	Payload    []byte
}

// MixForwardConfig controls randomized hop delay and forwarding batches.
type MixForwardConfig struct {
	HopDelayMin    time.Duration
	HopDelayMax    time.Duration
	BatchWindow    time.Duration
	BatchMax       int
	QueueCapacity  int
	ForwardTimeout time.Duration
}

// MixForwardMetrics reports queue and delay behavior for mix forwarding.
type MixForwardMetrics struct {
	HopDelayMinMS            uint64  `json:"hop_delay_min_ms"`
	HopDelayMaxMS            uint64  `json:"hop_delay_max_ms"`
	BatchWindowMS            uint64  `json:"batch_window_ms"`
	BatchMax                 int     `json:"batch_max"`
	QueueCapacity            int     `json:"queue_capacity"`
	QueueDepth               int     `json:"queue_depth"`
	Enqueued                 uint64  `json:"enqueued"`
	Forwarded                uint64  `json:"forwarded"`
	ForwardFailures          uint64  `json:"forward_failures"`
	Dropped                  uint64  `json:"dropped"`
	BatchesFlushed           uint64  `json:"batches_flushed"`
	LastBatchSize            int     `json:"last_batch_size"`
	AvgQueueDelayMS          float64 `json:"avg_queue_delay_ms"`
	LastBatchAvgQueueDelayMS float64 `json:"last_batch_avg_queue_delay_ms"`
}

type mixForwardRequest struct {
	targetURL  string
	msgID      string
	packet     []byte
	enqueuedAt time.Time
	result     chan error
}

type mixForwardStats struct {
	enqueued              uint64
	forwarded             uint64
	forwardFailures       uint64
	dropped               uint64
	batchesFlushed        uint64
	lastBatchSize         int
	queueDelayTotalMS     float64
	queueDelaySamples     uint64
	lastBatchQueueDelayMS float64
}

// MixForwarder applies per-hop delay and optional batch-window scheduling.
type MixForwarder struct {
	cfg    MixForwardConfig
	queue  chan mixForwardRequest
	stopCh chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	mu    sync.Mutex
	stats mixForwardStats
}

// PacketReplayCache tracks seen packet tags to reject replays per hop.
type PacketReplayCache struct {
	ttl        time.Duration
	maxEntries int
	mu         sync.Mutex
	seen       map[string]time.Time
}

// NewPacketReplayCacheFromEnv configures replay cache from env.
func NewPacketReplayCacheFromEnv() *PacketReplayCache {
	ttl := parseSecondsEnv("RELAY_MIX_TAG_TTL_SEC", defaultReplayTTL)
	maxEntries := parseIntEnv("RELAY_MIX_TAG_MAX_ENTRIES", defaultReplayMaxTag)
	if maxEntries <= 0 {
		maxEntries = defaultReplayMaxTag
	}
	return &PacketReplayCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		seen:       make(map[string]time.Time),
	}
}

func (c *PacketReplayCache) checkAndRemember(tag []byte) error {
	if c == nil {
		return nil
	}
	now := time.Now()
	key := hex.EncodeToString(tag)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)
	if exp, ok := c.seen[key]; ok && exp.After(now) {
		return ErrReplayTag
	}

	if len(c.seen) >= c.maxEntries {
		// Best effort memory cap: prune first, then drop an arbitrary stale slot.
		c.pruneLocked(now)
		if len(c.seen) >= c.maxEntries {
			for k := range c.seen {
				delete(c.seen, k)
				break
			}
		}
	}

	c.seen[key] = now.Add(c.ttl)
	return nil
}

func (c *PacketReplayCache) pruneLocked(now time.Time) {
	for tag, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, tag)
		}
	}
}

// LoadMixPrivateKeyFromEnv loads RELAY_MIX_PRIVATE_KEY_HEX when configured.
func LoadMixPrivateKeyFromEnv() ([]byte, bool, error) {
	raw := strings.TrimSpace(os.Getenv("RELAY_MIX_PRIVATE_KEY_HEX"))
	if raw == "" {
		return nil, false, nil
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, true, fmt.Errorf("invalid RELAY_MIX_PRIVATE_KEY_HEX: %w", err)
	}
	if len(key) != 32 {
		return nil, true, fmt.Errorf("RELAY_MIX_PRIVATE_KEY_HEX must decode to 32 bytes")
	}
	return key, true, nil
}

func normalizeMixForwardConfig(cfg MixForwardConfig) MixForwardConfig {
	if cfg.HopDelayMin < 0 {
		cfg.HopDelayMin = 0
	}
	if cfg.HopDelayMax < 0 {
		cfg.HopDelayMax = 0
	}
	if cfg.HopDelayMax < cfg.HopDelayMin {
		cfg.HopDelayMax = cfg.HopDelayMin
	}
	if cfg.BatchWindow < 0 {
		cfg.BatchWindow = 0
	}
	if cfg.BatchMax <= 0 {
		cfg.BatchMax = defaultMixBatchMax
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = defaultMixBatchQueueCapacity
	}
	if cfg.ForwardTimeout <= 0 {
		cfg.ForwardTimeout = defaultMixForwardTimeout
	}
	return cfg
}

// NewMixForwarderFromEnv configures mix-forward batching and delays.
func NewMixForwarderFromEnv() *MixForwarder {
	cfg := MixForwardConfig{
		HopDelayMin:    parseMillisEnv("RELAY_MIX_HOP_DELAY_MIN_MS", 0),
		HopDelayMax:    parseMillisEnv("RELAY_MIX_HOP_DELAY_MAX_MS", 0),
		BatchWindow:    parseMillisEnv("RELAY_MIX_BATCH_WINDOW_MS", 0),
		BatchMax:       parseIntEnv("RELAY_MIX_BATCH_MAX", defaultMixBatchMax),
		QueueCapacity:  parseIntEnv("RELAY_MIX_BATCH_QUEUE_CAPACITY", defaultMixBatchQueueCapacity),
		ForwardTimeout: parseMillisEnv("RELAY_MIX_FORWARD_TIMEOUT_MS", defaultMixForwardTimeout),
	}
	return NewMixForwarder(cfg)
}

// NewMixForwarder creates a reusable mix forward scheduler.
func NewMixForwarder(cfg MixForwardConfig) *MixForwarder {
	cfg = normalizeMixForwardConfig(cfg)
	f := &MixForwarder{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}

	if cfg.BatchWindow > 0 {
		f.queue = make(chan mixForwardRequest, cfg.QueueCapacity)
		f.wg.Add(1)
		go f.runBatchLoop()
	}

	return f
}

// Forward sends a packet to the next hop. In batch mode, it waits for flush completion.
func (f *MixForwarder) Forward(targetURL, msgID string, packet []byte) error {
	if f == nil {
		return ForwardSphinxPacket(targetURL, msgID, packet)
	}

	if f.queue == nil {
		return f.forwardOne(targetURL, msgID, packet, 0)
	}

	req := mixForwardRequest{
		targetURL:  targetURL,
		msgID:      msgID,
		packet:     append([]byte(nil), packet...),
		enqueuedAt: time.Now(),
		result:     make(chan error, 1),
	}

	select {
	case <-f.stopCh:
		return fmt.Errorf("mix forwarder stopped")
	case f.queue <- req:
		f.recordEnqueue()
	default:
		f.recordDrop()
		return ErrMixForwardQueueFull
	}

	timer := time.NewTimer(f.cfg.ForwardTimeout)
	defer timer.Stop()

	select {
	case err := <-req.result:
		return err
	case <-f.stopCh:
		return fmt.Errorf("mix forwarder stopped")
	case <-timer.C:
		return fmt.Errorf("mix forward timeout after %s", f.cfg.ForwardTimeout)
	}
}

// MetricsSnapshot returns current batching and queue-delay metrics.
func (f *MixForwarder) MetricsSnapshot() MixForwardMetrics {
	if f == nil {
		return MixForwardMetrics{}
	}

	queueDepth := 0
	if f.queue != nil {
		queueDepth = len(f.queue)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	avg := 0.0
	if f.stats.queueDelaySamples > 0 {
		avg = f.stats.queueDelayTotalMS / float64(f.stats.queueDelaySamples)
	}

	return MixForwardMetrics{
		HopDelayMinMS:            uint64(f.cfg.HopDelayMin / time.Millisecond),
		HopDelayMaxMS:            uint64(f.cfg.HopDelayMax / time.Millisecond),
		BatchWindowMS:            uint64(f.cfg.BatchWindow / time.Millisecond),
		BatchMax:                 f.cfg.BatchMax,
		QueueCapacity:            f.cfg.QueueCapacity,
		QueueDepth:               queueDepth,
		Enqueued:                 f.stats.enqueued,
		Forwarded:                f.stats.forwarded,
		ForwardFailures:          f.stats.forwardFailures,
		Dropped:                  f.stats.dropped,
		BatchesFlushed:           f.stats.batchesFlushed,
		LastBatchSize:            f.stats.lastBatchSize,
		AvgQueueDelayMS:          avg,
		LastBatchAvgQueueDelayMS: f.stats.lastBatchQueueDelayMS,
	}
}

// Close stops background batching and unblocks pending requests.
func (f *MixForwarder) Close() {
	if f == nil {
		return
	}
	f.once.Do(func() {
		close(f.stopCh)
		f.wg.Wait()
	})
}

func (f *MixForwarder) runBatchLoop() {
	defer f.wg.Done()

	batch := make([]mixForwardRequest, 0, f.cfg.BatchMax)
	var (
		flushTimer *time.Timer
		flushC     <-chan time.Time
	)

	stopTimer := func() {
		if flushTimer == nil {
			return
		}
		if !flushTimer.Stop() {
			select {
			case <-flushTimer.C:
			default:
			}
		}
		flushTimer = nil
		flushC = nil
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}

		now := time.Now()
		totalQueueDelayMS := 0.0
		for _, req := range batch {
			queueDelay := now.Sub(req.enqueuedAt)
			err := f.forwardOne(req.targetURL, req.msgID, req.packet, queueDelay)
			req.result <- err
			close(req.result)
			totalQueueDelayMS += float64(queueDelay) / float64(time.Millisecond)
		}

		avgQueueDelayMS := totalQueueDelayMS / float64(len(batch))
		f.recordBatch(len(batch), avgQueueDelayMS)
		batch = batch[:0]
	}

	for {
		if len(batch) == 0 {
			select {
			case <-f.stopCh:
				return
			case req := <-f.queue:
				batch = append(batch, req)
				flushTimer = time.NewTimer(f.cfg.BatchWindow)
				flushC = flushTimer.C
			}
			continue
		}

		if len(batch) >= f.cfg.BatchMax {
			stopTimer()
			flush()
			continue
		}

		select {
		case <-f.stopCh:
			stopTimer()
			for _, req := range batch {
				req.result <- fmt.Errorf("mix forwarder stopped")
				close(req.result)
			}
			return
		case req := <-f.queue:
			batch = append(batch, req)
		case <-flushC:
			stopTimer()
			flush()
		}
	}
}

func (f *MixForwarder) forwardOne(targetURL, msgID string, packet []byte, queueDelay time.Duration) error {
	f.applyHopDelay()
	err := ForwardSphinxPacket(targetURL, msgID, packet)
	f.recordForwardResult(err, queueDelay)
	return err
}

func (f *MixForwarder) applyHopDelay() {
	if f == nil {
		return
	}
	delay := f.cfg.HopDelayMin
	if f.cfg.HopDelayMax > f.cfg.HopDelayMin {
		delta := f.cfg.HopDelayMax - f.cfg.HopDelayMin
		delay += time.Duration(mrand.Int63n(int64(delta) + 1))
	}
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (f *MixForwarder) recordEnqueue() {
	f.mu.Lock()
	f.stats.enqueued++
	f.mu.Unlock()
}

func (f *MixForwarder) recordDrop() {
	f.mu.Lock()
	f.stats.dropped++
	f.mu.Unlock()
}

func (f *MixForwarder) recordForwardResult(err error, queueDelay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.stats.forwardFailures++
	} else {
		f.stats.forwarded++
	}
	delayMS := float64(queueDelay) / float64(time.Millisecond)
	if math.IsNaN(delayMS) || math.IsInf(delayMS, 0) || delayMS < 0 {
		delayMS = 0
	}
	f.stats.queueDelayTotalMS += delayMS
	f.stats.queueDelaySamples++
}

func (f *MixForwarder) recordBatch(size int, avgQueueDelayMS float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats.batchesFlushed++
	f.stats.lastBatchSize = size
	if math.IsNaN(avgQueueDelayMS) || math.IsInf(avgQueueDelayMS, 0) || avgQueueDelayMS < 0 {
		avgQueueDelayMS = 0
	}
	f.stats.lastBatchQueueDelayMS = avgQueueDelayMS
}

// ProcessSphinxPacket unwraps one packet for this hop, then either:
// - returns Forwarded=true with next hop and rewrapped payload, or
// - returns Final=true with receiver and final payload.
func ProcessSphinxPacket(privateKey []byte, blob []byte, replay *PacketReplayCache) (ProcessResult, error) {
	if len(privateKey) != 32 {
		return ProcessResult{}, fmt.Errorf("mix private key must be 32 bytes")
	}

	current := blob
	for depth := 0; depth < 8; depth++ {
		packet, err := parsePacket(current)
		if err != nil {
			if depth == 0 {
				return ProcessResult{}, err
			}
			return ProcessResult{}, fmt.Errorf("invalid nested mix packet: %w", err)
		}

		if err := replay.checkAndRemember(packet.tag); err != nil {
			return ProcessResult{}, err
		}

		plaintext, err := decryptPacket(privateKey, packet)
		if err != nil {
			return ProcessResult{}, fmt.Errorf("mix decrypt failed: %w", err)
		}

		var layer hopPayload
		if err := json.Unmarshal(plaintext, &layer); err != nil {
			return ProcessResult{}, fmt.Errorf("invalid mix hop payload: %w", err)
		}
		if layer.V != 1 {
			return ProcessResult{}, fmt.Errorf("unsupported mix payload version: %d", layer.V)
		}

		switch layer.Mode {
		case "rewrap":
			if len(layer.Payload) == 0 {
				return ProcessResult{}, fmt.Errorf("empty rewrap payload")
			}
			current = layer.Payload
			continue
		case "route":
			if layer.NextHop == "" || layer.NextHopPubKey == "" || len(layer.Payload) == 0 {
				return ProcessResult{}, fmt.Errorf("invalid route layer")
			}
			nextPub, err := hex.DecodeString(layer.NextHopPubKey)
			if err != nil || len(nextPub) != 32 {
				return ProcessResult{}, fmt.Errorf("invalid next hop public key")
			}

			rewrap := hopPayload{
				V:       1,
				Mode:    "rewrap",
				Payload: layer.Payload,
			}
			rewrapBytes, err := json.Marshal(rewrap)
			if err != nil {
				return ProcessResult{}, fmt.Errorf("failed to encode rewrap payload: %w", err)
			}
			wrapped, err := encryptPacket(nextPub, rewrapBytes)
			if err != nil {
				return ProcessResult{}, fmt.Errorf("failed to rewrap payload: %w", err)
			}

			return ProcessResult{
				Forwarded: true,
				NextHop:   layer.NextHop,
				Payload:   wrapped,
			}, nil
		case "final":
			if layer.FinalReceiver == "" {
				return ProcessResult{}, fmt.Errorf("final layer missing receiver")
			}
			return ProcessResult{
				Final:      true,
				ReceiverID: layer.FinalReceiver,
				Payload:    layer.Payload,
			}, nil
		default:
			return ProcessResult{}, fmt.Errorf("unknown mix layer mode: %s", layer.Mode)
		}
	}

	return ProcessResult{}, fmt.Errorf("mix unwrap depth exceeded")
}

// ForwardSphinxPacket forwards packet bytes to next hop relay endpoint.
func ForwardSphinxPacket(targetURL, msgID string, packet []byte) error {
	target := strings.TrimRight(targetURL, "/") + "/relay"
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(packet))
	if err != nil {
		return err
	}
	if strings.TrimSpace(msgID) == "" {
		msgID = randomMessageID()
	}
	req.Header.Set("X-Message-ID", msgID)
	req.Header.Set("X-Receiver-ID", "__mix__")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mixnet forward failed: %d", resp.StatusCode)
	}
	return nil
}

// MixAndForward remains for legacy/non-sphinx forwarding compatibility.
func MixAndForward(targetURL, msgID, receiver string, blob []byte) error {
	paddedBlob := addPadding(blob)
	time.Sleep(defaultLegacyMixForwardDelay)

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(targetURL, "/")+"/relay", bytes.NewBuffer(paddedBlob))
	if err != nil {
		return err
	}
	req.Header.Set("X-Message-ID", msgID)
	req.Header.Set("X-Receiver-ID", receiver)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mixnet forward failed: %d", resp.StatusCode)
	}

	return nil
}

type parsedPacket struct {
	tag        []byte
	ephemeral  []byte
	nonce      []byte
	ciphertext []byte
}

func parsePacket(blob []byte) (parsedPacket, error) {
	if len(blob) < mixPacketHeaderLen+16 {
		return parsedPacket{}, ErrNotMixPacket
	}
	if string(blob[:4]) != mixPacketMagic {
		return parsedPacket{}, ErrNotMixPacket
	}

	offset := 4
	tag := append([]byte(nil), blob[offset:offset+mixPacketTagLen]...)
	offset += mixPacketTagLen
	ephemeral := append([]byte(nil), blob[offset:offset+32]...)
	offset += 32
	nonce := append([]byte(nil), blob[offset:offset+12]...)
	offset += 12
	ciphertext := append([]byte(nil), blob[offset:]...)

	return parsedPacket{
		tag:        tag,
		ephemeral:  ephemeral,
		nonce:      nonce,
		ciphertext: ciphertext,
	}, nil
}

func decryptPacket(privateKey []byte, packet parsedPacket) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, packet.ephemeral)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, packet.nonce, packet.ciphertext, nil)
}

func encryptPacket(nextHopPubKey []byte, plaintext []byte) ([]byte, error) {
	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		return nil, err
	}
	ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := curve25519.X25519(ephemeralPriv[:], nextHopPubKey)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	tag := make([]byte, mixPacketTagLen)
	if _, err := rand.Read(tag); err != nil {
		return nil, err
	}

	packet := make([]byte, 0, mixPacketHeaderLen+len(ciphertext))
	packet = append(packet, []byte(mixPacketMagic)...)
	packet = append(packet, tag...)
	packet = append(packet, ephemeralPub...)
	packet = append(packet, nonce...)
	packet = append(packet, ciphertext...)
	return packet, nil
}

func randomMessageID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func addPadding(data []byte) []byte {
	const blockSize = 4096
	paddingLen := blockSize - (len(data) % blockSize)
	padding := make([]byte, paddingLen)
	if _, err := rand.Read(padding); err != nil {
		return data
	}
	return append(data, padding...)
}

func parseSecondsEnv(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

func parseMillisEnv(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

func parseIntEnv(key string, def int) int {
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
