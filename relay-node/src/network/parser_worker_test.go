package network

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"redoor-relay/src/onion"
)

func TestMain(m *testing.M) {
	if IsParserWorkerCommand(os.Args) {
		os.Exit(RunParserWorkerMain())
	}
	os.Exit(m.Run())
}

func TestParserWorkerDisabledReturnsUnavailable(t *testing.T) {
	t.Setenv("RELAY_PARSER_WORKER_ENABLED", "0")
	parser := newMixPacketParserFromEnv()
	defer parser.Close()

	_, err := parser.Process([]byte("invalid"))
	if !errors.Is(err, errParserWorkerUnavailable) {
		t.Fatalf("expected parser unavailable error, got %v", err)
	}
}

func TestParserWorkerRejectsInvalidMixPacket(t *testing.T) {
	t.Setenv("RELAY_PARSER_WORKER_ENABLED", "1")
	t.Setenv("RELAY_MIX_PRIVATE_KEY_HEX", strings.Repeat("11", 32))
	t.Setenv("RELAY_HMAC_KEY", "sensitive-hmac-key")
	t.Setenv("ADMIN_TOKEN", "sensitive-admin-token")

	parser := newMixPacketParserFromEnv()
	defer parser.Close()

	_, err := parser.Process([]byte("invalid-mix-packet"))
	if !errors.Is(err, onion.ErrNotMixPacket) {
		t.Fatalf("expected ErrNotMixPacket, got %v", err)
	}
}

func TestBuildParserWorkerEnv_AllowlistOnly(t *testing.T) {
	base := []string{
		"RELAY_MIX_PRIVATE_KEY_HEX=abc",
		"RELAY_MIX_TAG_TTL_SEC=60",
		"RELAY_HMAC_KEY=leak",
		"ADMIN_TOKEN=leak",
		"UNRELATED=ignored",
	}

	env := buildParserWorkerEnv(base)

	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "RELAY_HMAC_KEY" || key == "ADMIN_TOKEN" || key == "UNRELATED" {
			t.Fatalf("forbidden env key leaked into parser worker: %s", key)
		}
	}

	if !slices.Contains(env, "RELAY_MIX_PRIVATE_KEY_HEX=abc") {
		t.Fatalf("missing allowlisted key RELAY_MIX_PRIVATE_KEY_HEX in parser worker env")
	}
	if !slices.Contains(env, "RELAY_MIX_TAG_TTL_SEC=60") {
		t.Fatalf("missing allowlisted key RELAY_MIX_TAG_TTL_SEC in parser worker env")
	}
	if !slices.Contains(env, "GOMAXPROCS=1") {
		t.Fatalf("missing required GOMAXPROCS hardening in parser worker env")
	}
}

func TestParserWorkerForbiddenLeak_DetectsSensitiveKeys(t *testing.T) {
	leaks := parserWorkerForbiddenLeak([]string{
		"UNRELATED=1",
		"RELAY_HMAC_KEY=secret",
		"ADMIN_TOKEN=admin",
		"RELAY_HMAC_KEY=duplicate",
	})

	expected := []string{"ADMIN_TOKEN", "RELAY_HMAC_KEY"}
	if !slices.Equal(leaks, expected) {
		t.Fatalf("unexpected forbidden leak keys: got %v want %v", leaks, expected)
	}
}

func TestParserWorkerRecoversAfterCrash(t *testing.T) {
	t.Setenv("RELAY_PARSER_WORKER_ENABLED", "1")
	t.Setenv("RELAY_MIX_PRIVATE_KEY_HEX", strings.Repeat("22", 32))

	parser := newMixPacketParserFromEnv()
	defer parser.Close()

	client, ok := parser.(*parserWorkerClient)
	if !ok {
		t.Fatalf("expected parser worker client implementation")
	}

	client.mu.Lock()
	if client.cmd != nil && client.cmd.Process != nil {
		_ = client.cmd.Process.Kill()
	}
	client.mu.Unlock()

	time.Sleep(50 * time.Millisecond)

	_, err := parser.Process([]byte("invalid-mix-packet"))
	if !errors.Is(err, onion.ErrNotMixPacket) {
		t.Fatalf("expected ErrNotMixPacket after restart, got %v", err)
	}
}
