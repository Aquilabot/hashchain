package hashchain

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Reasons a verification can fail. A *VerifyError wraps exactly one of them,
// so callers can use errors.Is(err, hashchain.ErrHashMismatch) and so on.
var (
	// ErrHashMismatch: the stored hash does not match the recomputed hash.
	// The entry's content or its stored hash was modified.
	ErrHashMismatch = errors.New("hash mismatch")
	// ErrBrokenLink: the entry's PrevHash differs from the previous entry's
	// Hash. An entry was inserted, replaced or rehashed before this one.
	ErrBrokenLink = errors.New("prev hash does not match previous entry")
	// ErrSequence: sequence numbers are not contiguous (deleted, inserted or
	// reordered entries).
	ErrSequence = errors.New("sequence gap or reorder")
	// ErrGenesis: the first entry is not a valid genesis for this chain's
	// configuration (wrong hash function, key, or missing genesis).
	ErrGenesis = errors.New("invalid genesis entry")
	// ErrTruncated: entries that must exist (up to the requested end, or
	// the trusted checkpoint) are missing.
	ErrTruncated = errors.New("chain truncated")
	// ErrCheckpointMismatch: the stored entry at a trusted checkpoint has a
	// different hash than the checkpoint.
	ErrCheckpointMismatch = errors.New("checkpoint hash mismatch")
	// ErrUnknownVersion: no Codec is registered for the entry's version.
	ErrUnknownVersion = errors.New("unknown encoding version")
	// ErrEncoding: the entry could not be encoded (codec error).
	ErrEncoding = errors.New("entry cannot be encoded")
)

// VerifyError points at the first entry where verification failed.
type VerifyError struct {
	// Seq is the sequence number at which the chain breaks: the entry whose
	// check failed, or the expected position of a missing entry.
	Seq uint64
	// Reason is one of the Err* sentinels above.
	Reason error
	// Expected and Actual hold the compared values for hash and link
	// failures (digests), and are nil otherwise.
	Expected, Actual []byte
	// Detail is a human-readable explanation.
	Detail string
	// Err is an underlying error, for example from a Codec.
	Err error
}

func (e *VerifyError) Error() string {
	msg := fmt.Sprintf("hashchain: verification failed at seq %d: %v", e.Seq, e.Reason)
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	if e.Expected != nil || e.Actual != nil {
		msg += fmt.Sprintf(": expected %s, got %s", hexOrEmpty(e.Expected), hexOrEmpty(e.Actual))
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap lets errors.Is match both the Reason sentinel and Err.
func (e *VerifyError) Unwrap() []error {
	if e.Err != nil {
		return []error{e.Reason, e.Err}
	}
	return []error{e.Reason}
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	return hex.EncodeToString(b)
}
