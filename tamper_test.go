package hashchain

import (
	"slices"
	"testing"
	"time"
)

// forge recomputes e.Hash the way an attacker who knows the hash
// configuration (but, for keyed chains, not the key) would.
func forge(t *testing.T, c *Chain, e *Entry) {
	t.Helper()
	h, err := c.hashEntry(c.newDigester(), e)
	if err != nil {
		t.Fatal(err)
	}
	e.Hash = h
}

// The tamper matrix: each case mutates a healthy 10-entry chain (genesis at
// seq 0, entries 1..10) directly in the store and asserts the exact break
// point and reason reported by Verify.
func TestTamperMatrix(t *testing.T) {
	type tc struct {
		name   string
		keyed  bool
		tamper func(t *testing.T, c *Chain, s *MemoryStore)
		seq    uint64
		reason error
		// passes means plain Verify cannot see it; an anchored checkpoint
		// of the original head is then required to detect it.
		passes       bool
		anchorReason error
	}
	cases := []tc{
		{name: "edit payload", seq: 5, reason: ErrHashMismatch,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries[5].Payload = []byte(`{"i":999}`) }},
		{name: "edit kind", seq: 5, reason: ErrHashMismatch,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries[5].Kind = "other" }},
		{name: "edit time", seq: 5, reason: ErrHashMismatch,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries[5].Time = s.entries[5].Time.Add(time.Microsecond)
			}},
		{name: "edit stored hash", seq: 5, reason: ErrHashMismatch,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries[5].Hash[0] ^= 1 }},
		{name: "edit prev hash", seq: 5, reason: ErrBrokenLink,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries[5].PrevHash[0] ^= 1 }},
		{name: "edit and rehash", seq: 6, reason: ErrBrokenLink,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries[5].Payload = []byte("x")
				forge(t, c, &s.entries[5])
			}},
		{name: "edit and rehash, keyed chain", keyed: true, seq: 5, reason: ErrHashMismatch,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				attacker, _ := New(s, Config{}) // does not know the key
				s.entries[5].Payload = []byte("x")
				forge(t, attacker, &s.entries[5])
			}},
		{name: "delete middle", seq: 5, reason: ErrSequence,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries = slices.Delete(s.entries, 5, 6) }},
		{name: "delete middle and renumber", seq: 5, reason: ErrBrokenLink,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries = slices.Delete(s.entries, 5, 6)
				for i := 5; i < len(s.entries); i++ {
					s.entries[i].Seq--
				}
			}},
		{name: "delete genesis", seq: 0, reason: ErrGenesis,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries = s.entries[1:] }},
		{name: "edit genesis", seq: 0, reason: ErrGenesis,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries[0].Payload = []byte("hashchain-genesis/1\nhash=MD5")
				forge(t, c, &s.entries[0])
			}},
		{name: "reorder (swap seq numbers)", seq: 5, reason: ErrBrokenLink,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries[5], s.entries[6] = s.entries[6], s.entries[5]
				s.entries[5].Seq, s.entries[6].Seq = 5, 6
			}},
		{name: "reorder (store returns out of order)", seq: 5, reason: ErrSequence,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				s.entries[5], s.entries[6] = s.entries[6], s.entries[5]
			}},
		{name: "insert forged entry and renumber", seq: 7, reason: ErrBrokenLink,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				forged := Entry{Seq: 6, Version: V1, Time: s.entries[5].Time, Kind: "forged", PrevHash: s.entries[5].Hash}
				forge(t, c, &forged)
				s.entries = slices.Insert(s.entries, 6, forged)
				for i := 7; i < len(s.entries); i++ {
					s.entries[i].Seq++
				}
			}},
		{name: "insert duplicate seq", seq: 7, reason: ErrSequence,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				dup := s.entries[6].Clone()
				s.entries = slices.Insert(s.entries, 7, dup)
			}},
		{name: "truncate tail", passes: true, anchorReason: ErrTruncated, seq: 10,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) { s.entries = s.entries[:8] }},
		{name: "rewrite whole chain", passes: true, anchorReason: ErrCheckpointMismatch, seq: 10,
			tamper: func(t *testing.T, c *Chain, s *MemoryStore) {
				for i := 1; i < len(s.entries); i++ {
					s.entries[i].Payload = []byte("rewritten")
					s.entries[i].PrevHash = s.entries[i-1].Hash
					forge(t, c, &s.entries[i])
				}
			}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{}
			if tt.keyed {
				cfg.Key = []byte("k")
			}
			c, s := newTestChain(t, cfg, 10)
			anchor, _ := c.Head(ctx)
			if _, err := c.Verify(ctx); err != nil {
				t.Fatalf("healthy chain: %v", err)
			}
			// Deep-copy so that in-place edits do not alias.
			for i := range s.entries {
				s.entries[i] = s.entries[i].Clone()
			}
			tt.tamper(t, c, s)
			_, err := c.Verify(ctx)
			if tt.passes {
				if err != nil {
					t.Fatalf("expected plain Verify to pass (undetectable without an anchor), got %v", err)
				}
				_, err = c.VerifyFrom(ctx, anchor)
				assertBreak(t, err, tt.seq, tt.anchorReason)
				return
			}
			assertBreak(t, err, tt.seq, tt.reason)
		})
	}
}
