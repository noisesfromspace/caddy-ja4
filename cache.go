package ja4

import (
	"errors"
	"sync"
)

// ErrUnavailable signals that the JA4 fingerprint could not be computed.
var ErrUnavailable = errors.New("ja4 fingerprint unavailable")

// globalCache stores JA4 fingerprints keyed by connection remote address.
// It is populated by the TLS HandshakeContext callback and read by the HTTP handler.
var globalCache = &fingerprintCache{
	cache: make(map[string]string),
}

type fingerprintCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func (fc *fingerprintCache) get(addr string) (string, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	fp, ok := fc.cache[addr]
	return fp, ok
}

func (fc *fingerprintCache) set(addr string, fingerprint string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.cache[addr] = fingerprint
}

// cacheSet stores a JA4 fingerprint in the global cache.
// Called from the HandshakeContext callback.
func cacheSet(addr, fingerprint string) {
	globalCache.set(addr, fingerprint)
}

// GetFingerprintFromCache retrieves a JA4 fingerprint from the global cache
// by connection address. Used by the HTTP handler.
func GetFingerprintFromCache(addr string) (string, error) {
	fp, ok := globalCache.get(addr)
	if !ok {
		return "", ErrUnavailable
	}
	return fp, nil
}
