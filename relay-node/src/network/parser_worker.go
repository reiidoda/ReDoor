package network

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"redoor-relay/src/onion"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	parserWorkerCommandArg             = "parser-worker"
	defaultParserWorkerTimeout         = 1500 * time.Millisecond
	defaultParserWorkerMemoryLimitByte = int64(64 << 20)
)

var errParserWorkerUnavailable = errors.New("parser worker unavailable")

var parserWorkerAllowedEnvKeys = []string{
	"RELAY_MIX_PRIVATE_KEY_HEX",
	"RELAY_MIX_TAG_TTL_SEC",
	"RELAY_MIX_TAG_MAX_ENTRIES",
	"RELAY_PARSER_WORKER_MEM_LIMIT_BYTES",
}

var parserWorkerForbiddenEnvKeys = []string{
	"RELAY_HMAC_KEY",
	"ADMIN_TOKEN",
	"RELAY_KEY_FILE",
}

type mixPacketParser interface {
	Process(blob []byte) (onion.ProcessResult, error)
	Close()
}

type unavailableMixPacketParser struct{}

func (unavailableMixPacketParser) Process(_ []byte) (onion.ProcessResult, error) {
	return onion.ProcessResult{}, errParserWorkerUnavailable
}

func (unavailableMixPacketParser) Close() {}

type parserWorkerRequest struct {
	BlobBase64 string `json:"blob_base64"`
}

type parserWorkerResponse struct {
	OK         bool   `json:"ok"`
	Forwarded  bool   `json:"forwarded,omitempty"`
	Final      bool   `json:"final,omitempty"`
	NextHop    string `json:"next_hop,omitempty"`
	ReceiverID string `json:"receiver_id,omitempty"`
	PayloadB64 string `json:"payload_b64,omitempty"`
	ErrKind    string `json:"err_kind,omitempty"`
	ErrMsg     string `json:"err_msg,omitempty"`
}

type parserWorkerClient struct {
	mu       sync.Mutex
	execPath string
	timeout  time.Duration

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func newMixPacketParserFromEnv() mixPacketParser {
	if strings.TrimSpace(os.Getenv("RELAY_PARSER_WORKER_ENABLED")) == "0" {
		slog.Warn("Relay parser worker disabled via RELAY_PARSER_WORKER_ENABLED=0")
		return unavailableMixPacketParser{}
	}

	execPath, err := os.Executable()
	if err != nil {
		slog.Error("Failed to resolve relay executable path for parser worker", "error", err)
		return unavailableMixPacketParser{}
	}

	client := &parserWorkerClient{
		execPath: execPath,
		timeout:  parseParserWorkerTimeoutFromEnv(),
	}
	if err := client.ensureStartedLocked(); err != nil {
		slog.Error("Failed to start parser worker process", "error", err)
		return unavailableMixPacketParser{}
	}
	return client
}

func parseParserWorkerTimeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RELAY_PARSER_WORKER_TIMEOUT_MS"))
	if raw == "" {
		return defaultParserWorkerTimeout
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return defaultParserWorkerTimeout
	}
	return time.Duration(ms) * time.Millisecond
}

func (c *parserWorkerClient) Process(blob []byte) (onion.ProcessResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureStartedLocked(); err != nil {
		return onion.ProcessResult{}, errParserWorkerUnavailable
	}

	result, err := c.processOnceLocked(blob)
	if err == nil {
		return result, nil
	}

	// Restart once on transport/runtime failure; do not retry semantic parser rejections.
	if errors.Is(err, onion.ErrReplayTag) || errors.Is(err, onion.ErrNotMixPacket) {
		return onion.ProcessResult{}, err
	}

	c.stopLocked()
	if startErr := c.ensureStartedLocked(); startErr != nil {
		return onion.ProcessResult{}, errParserWorkerUnavailable
	}
	return c.processOnceLocked(blob)
}

func (c *parserWorkerClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

func (c *parserWorkerClient) processOnceLocked(blob []byte) (onion.ProcessResult, error) {
	req := parserWorkerRequest{
		BlobBase64: base64.StdEncoding.EncodeToString(blob),
	}
	line, err := json.Marshal(req)
	if err != nil {
		return onion.ProcessResult{}, fmt.Errorf("encode parser request: %w", err)
	}
	line = append(line, '\n')

	if _, err := c.stdin.Write(line); err != nil {
		return onion.ProcessResult{}, fmt.Errorf("write parser request: %w", err)
	}

	respBytes, err := c.readLineWithTimeoutLocked()
	if err != nil {
		return onion.ProcessResult{}, err
	}
	var resp parserWorkerResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return onion.ProcessResult{}, fmt.Errorf("decode parser response: %w", err)
	}

	if !resp.OK {
		switch resp.ErrKind {
		case "replay":
			return onion.ProcessResult{}, onion.ErrReplayTag
		case "not_mix":
			return onion.ProcessResult{}, onion.ErrNotMixPacket
		default:
			if strings.TrimSpace(resp.ErrMsg) == "" {
				return onion.ProcessResult{}, errors.New("parser worker rejected payload")
			}
			return onion.ProcessResult{}, errors.New(resp.ErrMsg)
		}
	}

	payload := []byte(nil)
	if resp.PayloadB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.PayloadB64)
		if err != nil {
			return onion.ProcessResult{}, fmt.Errorf("decode parser payload: %w", err)
		}
		payload = decoded
	}
	return onion.ProcessResult{
		Forwarded:  resp.Forwarded,
		Final:      resp.Final,
		NextHop:    resp.NextHop,
		ReceiverID: resp.ReceiverID,
		Payload:    payload,
	}, nil
}

func (c *parserWorkerClient) readLineWithTimeoutLocked() ([]byte, error) {
	type readResult struct {
		line []byte
		err  error
	}

	ch := make(chan readResult, 1)
	go func() {
		line, err := c.stdout.ReadBytes('\n')
		ch <- readResult{line: line, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("read parser response: %w", res.err)
		}
		return res.line, nil
	case <-time.After(c.timeout):
		return nil, fmt.Errorf("parser worker timeout after %s", c.timeout)
	}
}

func (c *parserWorkerClient) ensureStartedLocked() error {
	if c.cmd != nil && c.cmd.Process != nil {
		return nil
	}

	cmd := exec.Command(c.execPath, parserWorkerCommandArg)
	cmd.Env = buildParserWorkerEnv(os.Environ())

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	c.cmd = cmd
	c.stdin = stdin
	c.stdout = bufio.NewReader(stdout)

	go func(cmdRef *exec.Cmd) {
		if err := cmdRef.Wait(); err != nil {
			slog.Warn("Parser worker exited", "error", err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.cmd == cmdRef {
			c.cmd = nil
			c.stdin = nil
			c.stdout = nil
		}
	}(cmd)

	return nil
}

func (c *parserWorkerClient) stopLocked() {
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	c.cmd = nil
	c.stdin = nil
	c.stdout = nil
}

func IsParserWorkerCommand(args []string) bool {
	return len(args) > 1 && strings.TrimSpace(args[1]) == parserWorkerCommandArg
}

func RunParserWorkerMain() int {
	applyParserWorkerResourceLimits()

	if forbidden := parserWorkerForbiddenLeak(os.Environ()); len(forbidden) > 0 {
		slog.Error("Parser worker started with forbidden privileged env keys", "keys", forbidden)
		return 3
	}

	privateKey, enabled, err := onion.LoadMixPrivateKeyFromEnv()
	if err != nil || !enabled {
		slog.Error("Parser worker cannot start without valid mix key", "error", err, "mix_enabled", enabled)
		return 2
	}
	replay := onion.NewPacketReplayCacheFromEnv()

	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return 0
			}
			slog.Error("Parser worker read error", "error", readErr)
			return 1
		}
		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}

		var req parserWorkerRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = encoder.Encode(parserWorkerResponse{
				OK:      false,
				ErrKind: "invalid_request",
				ErrMsg:  "invalid parser request payload",
			})
			continue
		}

		blob, err := base64.StdEncoding.DecodeString(req.BlobBase64)
		if err != nil {
			_ = encoder.Encode(parserWorkerResponse{
				OK:      false,
				ErrKind: "invalid_request",
				ErrMsg:  "invalid base64 blob",
			})
			continue
		}

		result, err := onion.ProcessSphinxPacket(privateKey, blob, replay)
		if err != nil {
			errKind := "invalid_packet"
			if errors.Is(err, onion.ErrReplayTag) {
				errKind = "replay"
			} else if errors.Is(err, onion.ErrNotMixPacket) {
				errKind = "not_mix"
			}
			_ = encoder.Encode(parserWorkerResponse{
				OK:      false,
				ErrKind: errKind,
				ErrMsg:  err.Error(),
			})
			continue
		}

		_ = encoder.Encode(parserWorkerResponse{
			OK:         true,
			Forwarded:  result.Forwarded,
			Final:      result.Final,
			NextHop:    result.NextHop,
			ReceiverID: result.ReceiverID,
			PayloadB64: base64.StdEncoding.EncodeToString(result.Payload),
		})
	}
}

func applyParserWorkerResourceLimits() {
	runtime.GOMAXPROCS(1)
	debug.SetGCPercent(50)

	memoryLimit := defaultParserWorkerMemoryLimitByte
	if raw := strings.TrimSpace(os.Getenv("RELAY_PARSER_WORKER_MEM_LIMIT_BYTES")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			memoryLimit = parsed
		}
	}
	debug.SetMemoryLimit(memoryLimit)
}

func buildParserWorkerEnv(env []string) []string {
	allowed := make(map[string]string, len(parserWorkerAllowedEnvKeys))
	for _, entry := range env {
		key, val, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		for _, allowedKey := range parserWorkerAllowedEnvKeys {
			if key == allowedKey {
				allowed[key] = val
				break
			}
		}
	}

	out := make([]string, 0, len(allowed)+1)
	for _, key := range parserWorkerAllowedEnvKeys {
		if val, ok := allowed[key]; ok {
			out = append(out, key+"="+val)
		}
	}
	out = append(out, "GOMAXPROCS=1")
	return out
}

func parserWorkerForbiddenLeak(env []string) []string {
	leaks := make([]string, 0, len(parserWorkerForbiddenEnvKeys))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		for _, forbidden := range parserWorkerForbiddenEnvKeys {
			if key == forbidden {
				leaks = append(leaks, key)
				break
			}
		}
	}
	slices.Sort(leaks)
	return slices.Compact(leaks)
}
