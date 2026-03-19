package onion

import (
	"encoding/hex"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func makeRelayPeer(t *testing.T, url string) (RelayMixPeer, []byte) {
	t.Helper()
	priv, pub := mustKeypair(t)
	return RelayMixPeer{
		URL:       url,
		PublicKey: pub,
	}, priv
}

func TestRelayChaffGenerator_BuildsValidCoverPacketChain(t *testing.T) {
	peer1, priv1 := makeRelayPeer(t, "https://relay-a.example")
	peer2, priv2 := makeRelayPeer(t, "https://relay-b.example")
	peer3, priv3 := makeRelayPeer(t, "https://relay-c.example")

	privByURL := map[string][]byte{
		peer1.URL: priv1,
		peer2.URL: priv2,
		peer3.URL: priv3,
	}

	gen := NewRelayChaffGenerator(
		RelayChaffConfig{
			Enabled:      true,
			IntervalMin:  10 * time.Millisecond,
			IntervalMax:  10 * time.Millisecond,
			PayloadMin:   64,
			PayloadMax:   64,
			PathMinHops:  3,
			PathMaxHops:  3,
			BudgetPerMin: 10,
		},
		[]RelayMixPeer{peer1, peer2, peer3},
		nil,
	)

	entry, msgID, packet, err := gen.buildChaffPacket()
	if err != nil {
		t.Fatalf("build chaff packet: %v", err)
	}
	if entry == "" || msgID == "" || len(packet) == 0 {
		t.Fatalf("invalid chaff packet build output")
	}

	currentHop := entry
	currentPacket := packet
	for hop := 0; hop < 3; hop++ {
		priv := privByURL[currentHop]
		if len(priv) != 32 {
			t.Fatalf("missing private key for hop %q", currentHop)
		}

		res, err := ProcessSphinxPacket(priv, currentPacket, NewPacketReplayCacheFromEnv())
		if err != nil {
			t.Fatalf("process hop %d (%s): %v", hop, currentHop, err)
		}

		if hop < 2 {
			if !res.Forwarded || res.Final {
				t.Fatalf("hop %d expected forwarded route result", hop)
			}
			if res.NextHop == "" {
				t.Fatalf("hop %d expected non-empty next hop", hop)
			}
			currentHop = res.NextHop
			currentPacket = res.Payload
			continue
		}

		if !res.Final || res.Forwarded {
			t.Fatalf("final hop expected final delivery result")
		}
		if res.ReceiverID != "__cover__" {
			t.Fatalf("expected final receiver __cover__, got %q", res.ReceiverID)
		}
		if got := len(res.Payload); got != 64 {
			t.Fatalf("expected final cover payload 64 bytes, got %d", got)
		}
	}
}

func TestRelayChaffGenerator_BudgetGuardsThrottleExcessEmission(t *testing.T) {
	peer1, _ := makeRelayPeer(t, "https://relay-a.example")
	peer2, _ := makeRelayPeer(t, "https://relay-b.example")

	var sends atomic.Uint64
	gen := NewRelayChaffGenerator(
		RelayChaffConfig{
			Enabled:      true,
			IntervalMin:  1 * time.Millisecond,
			IntervalMax:  1 * time.Millisecond,
			PayloadMin:   32,
			PayloadMax:   32,
			PathMinHops:  2,
			PathMaxHops:  2,
			BudgetPerMin: 1,
		},
		[]RelayMixPeer{peer1, peer2},
		func(_ string, _ string, _ []byte) error {
			sends.Add(1)
			return nil
		},
	)

	gen.runOnce()
	gen.runOnce()

	metrics := gen.MetricsSnapshot()
	if sends.Load() != 1 {
		t.Fatalf("expected 1 send under budget, got %d", sends.Load())
	}
	if metrics.Generated != 1 || metrics.Forwarded != 1 {
		t.Fatalf("unexpected generated/forwarded counters: %+v", metrics)
	}
	if metrics.BudgetThrottled == 0 {
		t.Fatalf("expected budget throttling counter to increment")
	}
}

func TestRelayChaffGenerator_StartEmitsTrafficWithinBudget(t *testing.T) {
	peer1, _ := makeRelayPeer(t, "https://relay-a.example")
	peer2, _ := makeRelayPeer(t, "https://relay-b.example")

	var sends atomic.Uint64
	gen := NewRelayChaffGenerator(
		RelayChaffConfig{
			Enabled:      true,
			IntervalMin:  2 * time.Millisecond,
			IntervalMax:  2 * time.Millisecond,
			PayloadMin:   32,
			PayloadMax:   32,
			PathMinHops:  2,
			PathMaxHops:  2,
			BudgetPerMin: 6000, // generous budget for test run duration
		},
		[]RelayMixPeer{peer1, peer2},
		func(_ string, _ string, _ []byte) error {
			sends.Add(1)
			return nil
		},
	)

	gen.Start()
	time.Sleep(25 * time.Millisecond)
	gen.Close()

	metrics := gen.MetricsSnapshot()
	if sends.Load() == 0 || metrics.Generated == 0 || metrics.Forwarded == 0 {
		t.Fatalf("expected relay chaff emissions, got sends=%d metrics=%+v", sends.Load(), metrics)
	}
}

func TestParseRelayChaffPeersEnv_ParsesAndDedupes(t *testing.T) {
	_, pub1 := mustKeypair(t)
	_, pub2 := mustKeypair(t)
	raw := strings.Join([]string{
		"https://relay-a.example|" + hex.EncodeToString(pub1),
		"https://relay-a.example|" + hex.EncodeToString(pub1),
		"https://relay-b.example=" + hex.EncodeToString(pub2),
	}, ",")

	peers, err := parseRelayChaffPeersEnv(raw)
	if err != nil {
		t.Fatalf("parse relay peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 deduped peers, got %d", len(peers))
	}
}

func TestNewRelayChaffGeneratorFromEnv_InvalidPeersDisablesGenerator(t *testing.T) {
	t.Setenv("RELAY_CHAFF_ENABLED", "1")
	t.Setenv("RELAY_CHAFF_PEERS", "invalid-peer-entry")

	gen := NewRelayChaffGeneratorFromEnv(nil)
	metrics := gen.MetricsSnapshot()
	if metrics.Enabled {
		t.Fatalf("expected chaff generator to be disabled on invalid peers config")
	}
	if metrics.LastError == "" {
		t.Fatalf("expected invalid peers configuration error in metrics")
	}
}
