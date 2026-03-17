#!/bin/bash
# Reproducible build script
echo "Building Redoor Client..."
cd client && cargo build --release
echo "Building Redoor Relay..."
cd ../relay-node && go build -o relay src/main.go
echo "Building Redoor Blockchain..."
cd ../blockchain-node && cargo build --release
echo "Build complete."
