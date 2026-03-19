package onion

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type testHop struct {
	url string
	pub []byte
}

func mustKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand.Read private key: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return priv, pub
}

func buildSenderPacket(t *testing.T, path []testHop, finalReceiver string, payload []byte) []byte {
	t.Helper()

	final := hopPayload{
		V:             1,
		Mode:          "final",
		FinalReceiver: finalReceiver,
		Payload:       payload,
	}
	finalBytes, err := json.Marshal(final)
	if err != nil {
		t.Fatalf("marshal final hop payload: %v", err)
	}
	current, err := encryptPacket(path[len(path)-1].pub, finalBytes)
	if err != nil {
		t.Fatalf("encrypt final hop packet: %v", err)
	}

	for i := len(path) - 2; i >= 0; i-- {
		route := hopPayload{
			V:             1,
			Mode:          "route",
			NextHop:       path[i+1].url,
			NextHopPubKey: hex.EncodeToString(path[i+1].pub),
			Payload:       current,
		}
		routeBytes, err := json.Marshal(route)
		if err != nil {
			t.Fatalf("marshal route hop payload: %v", err)
		}
		current, err = encryptPacket(path[i].pub, routeBytes)
		if err != nil {
			t.Fatalf("encrypt route hop packet: %v", err)
		}
	}

	return current
}

func TestProcessSphinxPacket_EndToEndAndReplayProtection(t *testing.T) {
	hop1Priv, hop1Pub := mustKeypair(t)
	hop2Priv, hop2Pub := mustKeypair(t)
	hop3Priv, hop3Pub := mustKeypair(t)

	path := []testHop{
		{url: "https://relay-hop-1.example", pub: hop1Pub},
		{url: "https://relay-hop-2.example", pub: hop2Pub},
		{url: "https://relay-hop-3.example", pub: hop3Pub},
	}

	finalReceiver := "mailbox-abc"
	finalPayload := []byte("secret-message")
	packet := buildSenderPacket(t, path, finalReceiver, finalPayload)

	cache1 := NewPacketReplayCacheFromEnv()
	res1, err := ProcessSphinxPacket(hop1Priv, packet, cache1)
	if err != nil {
		t.Fatalf("hop1 process failed: %v", err)
	}
	if !res1.Forwarded || res1.Final {
		t.Fatalf("hop1 expected forwarded route result")
	}
	if res1.NextHop != path[1].url {
		t.Fatalf("hop1 next hop mismatch: got %q want %q", res1.NextHop, path[1].url)
	}
	if res1.ReceiverID != "" {
		t.Fatalf("hop1 should not expose final receiver")
	}

	if _, err := ProcessSphinxPacket(hop1Priv, packet, cache1); !errors.Is(err, ErrReplayTag) {
		t.Fatalf("expected replay rejection for repeated packet tag, got: %v", err)
	}

	cache2 := NewPacketReplayCacheFromEnv()
	res2, err := ProcessSphinxPacket(hop2Priv, res1.Payload, cache2)
	if err != nil {
		t.Fatalf("hop2 process failed: %v", err)
	}
	if !res2.Forwarded || res2.Final {
		t.Fatalf("hop2 expected forwarded route result")
	}
	if res2.NextHop != path[2].url {
		t.Fatalf("hop2 next hop mismatch: got %q want %q", res2.NextHop, path[2].url)
	}
	if res2.ReceiverID != "" {
		t.Fatalf("hop2 should not expose final receiver")
	}

	cache3 := NewPacketReplayCacheFromEnv()
	res3, err := ProcessSphinxPacket(hop3Priv, res2.Payload, cache3)
	if err != nil {
		t.Fatalf("hop3 process failed: %v", err)
	}
	if !res3.Final || res3.Forwarded {
		t.Fatalf("hop3 expected final delivery result")
	}
	if res3.ReceiverID != finalReceiver {
		t.Fatalf("final receiver mismatch: got %q want %q", res3.ReceiverID, finalReceiver)
	}
	if !bytes.Equal(res3.Payload, finalPayload) {
		t.Fatalf("final payload mismatch")
	}
}

func TestMixForwarder_AppliesBoundedHopDelay(t *testing.T) {
	received := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Receiver-ID"); got != "__mix__" {
			t.Fatalf("unexpected receiver header: %q", got)
		}
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	forwarder := NewMixForwarder(MixForwardConfig{
		HopDelayMin:    30 * time.Millisecond,
		HopDelayMax:    30 * time.Millisecond,
		BatchWindow:    0,
		BatchMax:       1,
		QueueCapacity:  1,
		ForwardTimeout: 2 * time.Second,
	})
	defer forwarder.Close()

	started := time.Now()
	if err := forwarder.Forward(target.URL, "delay-test", []byte("packet")); err != nil {
		t.Fatalf("forward failed: %v", err)
	}
	elapsed := time.Since(started)

	if elapsed < 25*time.Millisecond {
		t.Fatalf("hop delay not applied: elapsed=%s", elapsed)
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("hop delay exceeded expected bound: elapsed=%s", elapsed)
	}

	select {
	case <-received:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("target relay did not receive forwarded packet")
	}

	metrics := forwarder.MetricsSnapshot()
	if metrics.Forwarded != 1 {
		t.Fatalf("expected forwarded=1, got %d", metrics.Forwarded)
	}
	if metrics.BatchesFlushed != 0 {
		t.Fatalf("direct mode should not flush batches, got %d", metrics.BatchesFlushed)
	}
	if metrics.HopDelayMinMS != 30 || metrics.HopDelayMaxMS != 30 {
		t.Fatalf("unexpected delay bounds in metrics: min=%d max=%d", metrics.HopDelayMinMS, metrics.HopDelayMaxMS)
	}
}

func TestMixForwarder_BatchesWithinWindowAndPublishesMetrics(t *testing.T) {
	const sends = 3

	var (
		mu       sync.Mutex
		received = make([]string, 0, sends)
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Header.Get("X-Message-ID"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	forwarder := NewMixForwarder(MixForwardConfig{
		HopDelayMin:    0,
		HopDelayMax:    0,
		BatchWindow:    80 * time.Millisecond,
		BatchMax:       8,
		QueueCapacity:  16,
		ForwardTimeout: 2 * time.Second,
	})
	defer forwarder.Close()

	start := make(chan struct{})
	errCh := make(chan error, sends)
	var wg sync.WaitGroup
	started := time.Now()
	for i := 0; i < sends; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errCh <- forwarder.Forward(target.URL, fmt.Sprintf("batch-%d", idx), []byte{byte(idx)})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)
	elapsed := time.Since(started)

	for err := range errCh {
		if err != nil {
			t.Fatalf("batched forward failed: %v", err)
		}
	}

	if elapsed < 60*time.Millisecond {
		t.Fatalf("batch window not enforced: elapsed=%s", elapsed)
	}

	mu.Lock()
	got := len(received)
	mu.Unlock()
	if got != sends {
		t.Fatalf("expected %d forwarded packets, got %d", sends, got)
	}

	metrics := forwarder.MetricsSnapshot()
	if metrics.BatchesFlushed == 0 {
		t.Fatalf("expected at least one batch flush, got %d", metrics.BatchesFlushed)
	}
	if metrics.LastBatchSize != sends {
		t.Fatalf("expected last batch size %d, got %d", sends, metrics.LastBatchSize)
	}
	if metrics.AvgQueueDelayMS < 20 {
		t.Fatalf("expected non-trivial queue delay, got %.2fms", metrics.AvgQueueDelayMS)
	}
	if metrics.BatchWindowMS != 80 {
		t.Fatalf("expected batch window 80ms, got %d", metrics.BatchWindowMS)
	}
}
