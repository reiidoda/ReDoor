package network

import (
	"bytes"
	"fmt"
	"net/http"
)

// ForwardBlob sends a blob to another relay or client (for multi-hop)
func ForwardBlob(targetURL string, id string, data []byte) error {
	// Construct payload: ID + Data
	payload := append([]byte(id), data...)

	resp, err := http.Post(targetURL+"/relay", "application/octet-stream", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to forward blob: status %d", resp.StatusCode)
	}

	return nil
}
