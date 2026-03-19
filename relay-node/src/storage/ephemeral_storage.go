package storage

import (
	"log/slog"
	"sync"
	"time"
)

// Blob represents an encrypted message blob
type Blob struct {
	Data         []byte
	CreatedAt    time.Time
	IsPersistent bool
}

// EphemeralStore provides thread-safe in-memory storage
type EphemeralStore struct {
	blobs         map[string]Blob
	receiverIndex map[string][]string // receiver_id -> list of message IDs
	msgToReceiver map[string]string   // msg_id -> receiver_id
	mu            sync.RWMutex
}

// NewStore creates a new EphemeralStore
func NewStore() *EphemeralStore {
	store := &EphemeralStore{
		blobs:         make(map[string]Blob),
		receiverIndex: make(map[string][]string),
		msgToReceiver: make(map[string]string),
	}
	// Start cleanup routine
	go store.cleanupLoop()
	return store
}

// Store saves a blob with a given ID
func (s *EphemeralStore) Store(id string, receiver string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[id] = Blob{
		Data:      data,
		CreatedAt: time.Now(),
	}
	s.receiverIndex[receiver] = append(s.receiverIndex[receiver], id)
	s.msgToReceiver[id] = receiver
}

// StorePersistent saves a blob that persists after retrieval (e.g. for Prekeys)
func (s *EphemeralStore) StorePersistent(id string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[id] = Blob{
		Data:         data,
		CreatedAt:    time.Now(),
		IsPersistent: true,
	}
}

// Count returns the number of pending blobs for a receiver
func (s *EphemeralStore) Count(receiver string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.receiverIndex[receiver])
}

// Retrieve gets a blob by ID and deletes it (fetch-once)
func (s *EphemeralStore) Retrieve(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blob, exists := s.blobs[id]
	if !exists {
		return nil, false
	}

	// Delete immediately after retrieval only if not persistent
	if !blob.IsPersistent {
		delete(s.blobs, id)
		s.removeIDFromReceivers(id)
		delete(s.msgToReceiver, id)
	}
	return blob.Data, true
}

// RetrieveNextByReceiver pops the oldest blob for a given receiver
func (s *EphemeralStore) RetrieveNextByReceiver(receiver string) (string, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, ok := s.receiverIndex[receiver]
	if !ok || len(ids) == 0 {
		return "", nil, false
	}
	id := ids[0]
	s.receiverIndex[receiver] = ids[1:]
	if len(s.receiverIndex[receiver]) == 0 {
		delete(s.receiverIndex, receiver)
	}

	delete(s.msgToReceiver, id)
	blob, exists := s.blobs[id]
	if !exists {
		return "", nil, false
	}
	if !blob.IsPersistent {
		delete(s.blobs, id)
	}
	return id, blob.Data, true
}

func (s *EphemeralStore) removeIDFromReceivers(id string) {
	receiver, ok := s.msgToReceiver[id]
	if !ok {
		return
	}
	ids := s.receiverIndex[receiver]
	newIDs := make([]string, 0, len(ids))
	for _, candidate := range ids {
		if candidate != id {
			newIDs = append(newIDs, candidate)
		}
	}
	if len(newIDs) == 0 {
		delete(s.receiverIndex, receiver)
	} else {
		s.receiverIndex[receiver] = newIDs
	}
}

// cleanupLoop periodically removes old blobs (TTL)
func (s *EphemeralStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		deletedCount := 0
		for id, blob := range s.blobs {
			// Persistent blobs have a longer TTL (e.g. 30 days)
			ttl := 24 * time.Hour
			if blob.IsPersistent {
				ttl = 720 * time.Hour // 30 days
			}
			if now.Sub(blob.CreatedAt) > ttl {
				delete(s.blobs, id)
				s.removeIDFromReceivers(id)
				delete(s.msgToReceiver, id)
				deletedCount++
			}
		}
		s.mu.Unlock()
		if deletedCount > 0 {
			slog.Info("Cleanup loop ran", "deleted_blobs", deletedCount)
		}
	}
}
