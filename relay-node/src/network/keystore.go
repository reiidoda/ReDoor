package network

import "sync/atomic"

// KeyStore holds an optional HMAC key that can be rotated at runtime.
type KeyStore struct {
	key atomic.Value // []byte or nil
}

func NewKeyStore(initial []byte) *KeyStore {
	ks := &KeyStore{}
	if initial != nil {
		ks.key.Store(initial)
	}
	return ks
}

func (ks *KeyStore) Get() []byte {
	v := ks.key.Load()
	if v == nil {
		return nil
	}
	return v.([]byte)
}

func (ks *KeyStore) Set(newKey []byte) {
	if newKey == nil {
		ks.key.Store(nil)
		return
	}
	ks.key.Store(newKey)
}
