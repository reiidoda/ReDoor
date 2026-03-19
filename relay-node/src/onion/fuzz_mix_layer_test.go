package onion

import (
	"testing"
	"time"
)

func FuzzProcessSphinxPacket(f *testing.F) {
	f.Add(make([]byte, 32), []byte("not-a-mix-packet"))
	f.Add(make([]byte, 32), make([]byte, 0))

	replay := &PacketReplayCache{
		ttl:        defaultReplayTTL,
		maxEntries: 256,
		seen:       make(map[string]time.Time),
	}

	f.Fuzz(func(_ *testing.T, key, blob []byte) {
		private := make([]byte, 32)
		copy(private, key)
		_, _ = ProcessSphinxPacket(private, blob, replay)
	})
}
