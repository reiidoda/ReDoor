package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"redoor-relay/src/network"
	"redoor-relay/src/storage"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if network.IsParserWorkerCommand(os.Args) {
		os.Exit(network.RunParserWorkerMain())
	}

	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("Starting Redoor Relay Node...")

	// Initialize ephemeral storage
	store := storage.NewStore()

	// Optional HMAC key for integrity (base64-encoded in env RELAY_HMAC_KEY)
	var hmacKey []byte
	if keyB64 := os.Getenv("RELAY_HMAC_KEY"); keyB64 != "" {
		k, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			logger.Error("Invalid RELAY_HMAC_KEY base64", "error", err)
			os.Exit(1)
		}
		hmacKey = k
		logger.Info("Relay HMAC integrity enabled")
	}
	ks := network.NewKeyStore(hmacKey)
	requireScopedAuth := os.Getenv("RELAY_REQUIRE_SCOPED_AUTH") == "1"
	credentialTTL := parseIntEnv("RELAY_CLIENT_CREDENTIAL_TTL_SEC", 3600)
	credentialRotateOverlap := parseIntEnv("RELAY_CLIENT_CREDENTIAL_ROTATION_OVERLAP_SEC", 300)
	credentialStore := network.NewCredentialStore(time.Duration(credentialTTL) * time.Second)

	// Rate limiting (per-IP token bucket). Defaults: 20 rps, burst 40.
	rps, burst := network.ParseRateEnv(os.Getenv("RELAY_RPS"), os.Getenv("RELAY_BURST"), 20, 40)
	rl := network.NewRateLimiter(rps, burst)

	// Per-receiver quota (max pending blobs). Defaults: 100.
	maxPending := parseIntEnv("RELAY_MAX_PENDING", 100)
	// Max relay payload size in bytes. Defaults: 256 KiB.
	maxBlobBytes := parseIntEnv("RELAY_MAX_BLOB_BYTES", 256*1024)
	abuse := network.NewAbuseControllerFromEnv(maxPending)

	mux := http.NewServeMux()

	// Mixnet configuration: comma-separated list of next-hop relay base URLs.
	nextHops := parseNextHops(os.Getenv("RELAY_NEXT_HOPS"))
	isExit := os.Getenv("RELAY_MIX_EXIT") == "1"

	// Set up network handlers
	mux.HandleFunc("/auth/register", rl.Wrap(network.HandleAuthRegister(credentialStore)))
	mux.HandleFunc("/auth/refresh", rl.Wrap(network.HandleAuthRefresh(credentialStore)))
	mux.HandleFunc("/relay", rl.Wrap(network.HandleRelayWithAbuse(store, ks, credentialStore, requireScopedAuth, maxPending, maxBlobBytes, nextHops, isExit, abuse)))
	mux.HandleFunc("/fetch", rl.Wrap(network.HandleFetchWithAbuse(store, ks, credentialStore, requireScopedAuth, abuse)))
	mux.HandleFunc("/fetch_pending", rl.Wrap(network.HandleFetchPendingWithAbuse(store, ks, credentialStore, requireScopedAuth, abuse)))
	mux.HandleFunc("/fetch_pending_batch", rl.Wrap(network.HandleFetchPendingBatchWithAbuse(store, ks, credentialStore, requireScopedAuth, abuse)))
	mux.HandleFunc("/metrics/abuse", network.HandleAbuseMetrics(abuse))
	mux.HandleFunc("/metrics/mix", network.HandleMixMetrics())
	mux.HandleFunc("/metrics/chaff", network.HandleChaffMetrics())

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
			return
		}
	})

	// Admin endpoint to rotate HMAC key at runtime (optional)
	adminToken := os.Getenv("ADMIN_TOKEN")
	registerAdminRoutes(
		mux,
		ks,
		credentialStore,
		adminToken,
		time.Duration(credentialRotateOverlap)*time.Second,
	)

	// TLS configuration (required). Set RELAY_CERT_FILE and RELAY_KEY_FILE.
	certFile := os.Getenv("RELAY_CERT_FILE")
	keyFile := os.Getenv("RELAY_KEY_FILE")
	if certFile == "" || keyFile == "" {
		logger.Error("RELAY_CERT_FILE and RELAY_KEY_FILE must be set (TLS is mandatory)")
		os.Exit(1)
	}

	tlsConfig, err := tlsConfig(certFile, keyFile)
	if err != nil {
		logger.Error("TLS config error", "error", err)
		os.Exit(1)
	}

	addr := getenvDefault("RELAY_ADDR", ":8443")

	srv := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}

	// Optional HTTP->HTTPS redirect helper (disabled by default)
	if redirectPort := os.Getenv("RELAY_REDIRECT_HTTP"); redirectPort != "" {
		go func() {
			from := ":8080"
			if redirectPort != "1" {
				from = redirectPort
			}
			logger.Info("HTTP redirector listening", "from", from, "to", addr)
			_ = http.ListenAndServe(from, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.String()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))
		}()
	}

	// Graceful shutdown
	go func() {
		logger.Info("Relay Node listening", "addr", addr)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exiting")
}

func parseIntEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseNextHops(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	hops := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			hops = append(hops, trimmed)
		}
	}
	return hops
}

func registerAdminRoutes(
	mux *http.ServeMux,
	ks *network.KeyStore,
	credentialStore *network.CredentialStore,
	adminToken string,
	credentialRotateOverlap time.Duration,
) {
	if strings.TrimSpace(adminToken) == "" {
		// Endpoint is intentionally disabled unless explicitly configured.
		return
	}

	mux.HandleFunc("/admin/hmac", func(w http.ResponseWriter, r *http.Request) {
		if !adminTokenAuthorized(r.Header.Get("X-Admin-Token"), adminToken) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		newKey, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			http.Error(w, "Invalid base64 key", http.StatusBadRequest)
			return
		}
		ks.Set(newKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "HMAC key rotated, length=%d", len(newKey))
	})

	mux.HandleFunc(
		"/admin/scoped/revoke",
		network.HandleAuthRevoke(credentialStore, adminToken),
	)
	mux.HandleFunc(
		"/admin/scoped/rotate",
		network.HandleAuthRotate(credentialStore, adminToken, credentialRotateOverlap),
	)
}

func adminTokenAuthorized(provided, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// Enforce TLS settings and load the cert/key pair
func tlsConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		// HTTP/2 is on by default with Go's server when TLS is 1.2+ and
		// certificates are configured.
	}, nil
}

// securityHeaders adds HSTS and basic anti-sniff protections.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// Relay responses do not set cache headers intentionally (they are ephemeral)
		next.ServeHTTP(w, r)
	})
}
