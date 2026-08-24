// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjwt

import "sync"

// MemNonceStore is an in-memory NonceStore used for DA nonce / jti
// replay prevention.  Suitable for single-process reference
// deployments; production deployments MUST use a persistent store.
type MemNonceStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewMemNonceStore creates an empty in-memory nonce store.
func NewMemNonceStore() *MemNonceStore {
	return &MemNonceStore{seen: make(map[string]struct{})}
}

// CheckAndAdd records the nonce, rejecting duplicates.
func (m *MemNonceStore) CheckAndAdd(nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[nonce]; ok {
		return &NonceReuseError{Nonce: nonce}
	}
	m.seen[nonce] = struct{}{}
	return nil
}

// NonceReuseError reports a replayed DA nonce.
type NonceReuseError struct {
	Nonce string
}

func (e *NonceReuseError) Error() string {
	return "nonce reuse: " + e.Nonce
}
