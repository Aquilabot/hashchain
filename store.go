package hashchain

import (
	"context"
	"sort"
	"sync"
)

// Store persists the entries of one chain.
//
// Implementations must make Append atomic and mutually exclusive: while one
// Append runs build and writes its result, no other Append on the same chain
// (in this process or any other) may observe the old head. That is what keeps
// the chain from forking under concurrent writers.
type Store interface {
	// Append reads the current head (nil when the chain is empty), calls
	// build with it while holding exclusive write access to the chain, and
	// atomically persists the returned entries. The head passed to build is
	// guaranteed to carry Seq and Hash; other fields may be empty. If build
	// returns an error nothing is written and the error is returned.
	Append(ctx context.Context, build func(head *Entry) ([]Entry, error)) error

	// Head returns the last entry, or (nil, nil) when the chain is empty.
	Head(ctx context.Context) (*Entry, error)

	// Scan calls fn for every entry with from <= Seq <= to, in ascending Seq
	// order, stopping at the first error. Implementations should stream
	// rather than load the whole range. The *Entry and its slices are only
	// valid during the call; fn must copy anything it keeps.
	Scan(ctx context.Context, from, to uint64, fn func(*Entry) error) error
}

// MemoryStore is a Store backed by a slice. It is safe for concurrent use
// and is intended for tests, examples and short-lived processes.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []Entry
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

// Append implements Store.
func (s *MemoryStore) Append(ctx context.Context, build func(head *Entry) ([]Entry, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var head *Entry
	if n := len(s.entries); n > 0 {
		h := s.entries[n-1]
		head = &h
	}
	out, err := build(head)
	if err != nil {
		return err
	}
	for i := range out {
		s.entries = append(s.entries, out[i].Clone())
	}
	return nil
}

// Head implements Store.
func (s *MemoryStore) Head(ctx context.Context) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil, nil
	}
	h := s.entries[len(s.entries)-1].Clone()
	return &h, nil
}

// Scan implements Store. Entries appended after Scan starts are not visited.
func (s *MemoryStore) Scan(ctx context.Context, from, to uint64, fn func(*Entry) error) error {
	s.mu.RLock()
	snapshot := s.entries // existing elements are never modified in place
	s.mu.RUnlock()
	start := sort.Search(len(snapshot), func(i int) bool { return snapshot[i].Seq >= from })
	var e Entry // reused across iterations; see the Store.Scan contract
	for i := start; i < len(snapshot); i++ {
		e = snapshot[i]
		if e.Seq > to {
			break
		}
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err := fn(&e); err != nil {
			return err
		}
	}
	return nil
}

// Len returns the number of stored entries.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
