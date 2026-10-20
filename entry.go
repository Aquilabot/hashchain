// Package hashchain implements an append-only, tamper-evident log in which
// every entry commits to the hash of the entry before it.
//
// A Chain computes and verifies hashes; a Store persists entries. The package
// ships an in-memory Store (NewMemoryStore) and a Postgres Store in the
// pgstore subpackage. Entries are hashed over a canonical, versioned binary
// encoding described in Codec and in the README.
package hashchain

import (
	"bytes"
	"time"
)

// Entry is one record of a chain as it is persisted.
type Entry struct {
	// Seq is the position of the entry in the chain. The genesis entry has
	// Seq 0 and the first application entry has Seq 1. Sequence numbers are
	// contiguous.
	Seq uint64
	// Version selects the Codec used to hash the entry.
	Version uint8
	// Time is the append time, in UTC, truncated to whole microseconds.
	Time time.Time
	// Kind is an application-defined label, for example "user.login". It must
	// be valid UTF-8, non-empty and free of NUL bytes.
	Kind string
	// Payload is opaque application data. The chain never interprets it.
	Payload []byte
	// PrevHash is the Hash of the entry at Seq-1, or empty for the first
	// entry of the chain.
	PrevHash []byte
	// Hash is the digest of the entry's canonical encoding.
	Hash []byte
}

// Clone returns a deep copy of e.
func (e *Entry) Clone() Entry {
	c := *e
	c.Payload = bytes.Clone(e.Payload)
	c.PrevHash = bytes.Clone(e.PrevHash)
	c.Hash = bytes.Clone(e.Hash)
	return c
}

// Checkpoint identifies a chain state by the sequence number and hash of its
// last entry. Publishing checkpoints outside the store (external anchoring)
// is what lets a verifier detect a rewritten or truncated chain.
type Checkpoint struct {
	Seq  uint64
	Hash []byte
}

// IsZero reports whether c is the empty checkpoint (no entries).
func (c Checkpoint) IsZero() bool { return c.Seq == 0 && len(c.Hash) == 0 }

// Record is the input to Chain.Append.
type Record struct {
	// Kind is required; see Entry.Kind.
	Kind string
	// Payload is optional opaque data.
	Payload []byte
	// Time is optional. The zero value means "now" (Config.Now). It is
	// converted to UTC and truncated to microseconds before hashing.
	Time time.Time
}

// Report summarizes a successful verification.
type Report struct {
	// Entries is the number of entries whose hash was recomputed.
	Entries uint64
	// First and Last are the first and last verified entries. Both are zero
	// when nothing was verified.
	First Checkpoint
	Last  Checkpoint
}
