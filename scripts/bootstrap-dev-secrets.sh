#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

relay_cert="$ROOT/relay-node/cert.pem"
relay_key="$ROOT/relay-node/key.pem"
node_key_hex="$ROOT/blockchain-node/node_key.hex"

mkdir -p "$ROOT/relay-node" "$ROOT/blockchain-node"

if [[ ! -f "$relay_cert" || ! -f "$relay_key" ]]; then
  openssl req \
    -x509 \
    -newkey rsa:4096 \
    -sha256 \
    -days 365 \
    -nodes \
    -subj "/CN=localhost" \
    -keyout "$relay_key" \
    -out "$relay_cert" \
    >/dev/null 2>&1
  chmod 600 "$relay_key"
  chmod 644 "$relay_cert"
  echo "Generated relay TLS keypair in relay-node/."
else
  echo "Relay TLS keypair already exists; skipping generation."
fi

if [[ ! -f "$node_key_hex" ]]; then
  openssl rand -hex 32 >"$node_key_hex"
  chmod 600 "$node_key_hex"
  echo "Generated blockchain node key in blockchain-node/node_key.hex."
else
  echo "Blockchain node key already exists; skipping generation."
fi

echo "Local dev secrets bootstrap complete."
