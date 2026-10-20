package hashchain

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func fixedClock() func() time.Time {
	var mu sync.Mutex
	t := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(time.Millisecond)
		return t
	}
}

func newTestChain(t testing.TB, cfg Config, n int) (*Chain, *MemoryStore) {
	t.Helper()
	s := NewMemoryStore()
	if cfg.Now == nil {
		cfg.Now = fixedClock()
	}
	c, err := New(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := c.Append(ctx, Record{Kind: "test.event", Payload: []byte(fmt.Sprintf(`{"i":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	return c, s
}

func TestAppendAndVerify(t *testing.T) {
	c, s := newTestChain(t, Config{}, 10)
	if s.Len() != 11 { // genesis + 10
		t.Fatalf("len = %d, want 11", s.Len())
	}
	rep, err := c.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 11 || rep.First.Seq != 0 || rep.Last.Seq != 10 {
		t.Fatalf("report = %+v", rep)
	}
	head, _ := c.Head(ctx)
	if head.Seq != 10 || !bytes.Equal(head.Hash, rep.Last.Hash) {
		t.Fatalf("head %+v != report last %+v", head, rep.Last)
	}
}

func TestAppendReturnsStoredEntry(t *testing.T) {
	c, s := newTestChain(t, Config{}, 0)
	e, err := c.Append(ctx, Record{Kind: "k", Payload: []byte("p"), Time: time.Date(2026, 5, 1, 0, 0, 0, 999, time.FixedZone("x", 3600))})
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 1 || e.Time.Location() != time.UTC || e.Time.Nanosecond() != 0 {
		t.Fatalf("unexpected entry %+v", e)
	}
	var stored Entry
	_ = s.Scan(ctx, 1, 1, func(x *Entry) error { stored = x.Clone(); return nil })
	if !bytes.Equal(stored.Hash, e.Hash) || !bytes.Equal(stored.PrevHash, e.PrevHash) || !stored.Time.Equal(e.Time) {
		t.Fatalf("stored %+v, returned %+v", stored, e)
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	c, _ := newTestChain(t, Config{}, 0)
	rep, err := c.Verify(ctx)
	if err != nil || rep.Entries != 0 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestNoGenesisStartsAtOne(t *testing.T) {
	c, s := newTestChain(t, Config{NoGenesis: true}, 3)
	if s.Len() != 3 {
		t.Fatalf("len = %d", s.Len())
	}
	var first Entry
	_ = s.Scan(ctx, 0, 1, func(e *Entry) error { first = e.Clone(); return nil })
	if first.Seq != 1 || len(first.PrevHash) != 0 {
		t.Fatalf("first = %+v", first)
	}
	if _, err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBatchEqualsSequentialStructure(t *testing.T) {
	c, s := newTestChain(t, Config{}, 0)
	recs := make([]Record, 50)
	for i := range recs {
		recs[i] = Record{Kind: "batch", Payload: []byte{byte(i)}}
	}
	out, err := c.AppendBatch(ctx, recs...)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 50 || out[0].Seq != 1 || out[49].Seq != 50 {
		t.Fatalf("batch out: len=%d", len(out))
	}
	if s.Len() != 51 {
		t.Fatalf("len=%d", s.Len())
	}
	if _, err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidKind(t *testing.T) {
	c, _ := newTestChain(t, Config{}, 0)
	for _, k := range []string{"", "a\x00b", string([]byte{0xff})} {
		if _, err := c.Append(ctx, Record{Kind: k}); err == nil {
			t.Errorf("kind %q accepted", k)
		}
	}
}

func TestKeyedChain(t *testing.T) {
	store := NewMemoryStore()
	keyed, _ := New(store, Config{Key: []byte("secret"), Now: fixedClock()})
	for i := 0; i < 5; i++ {
		if _, err := keyed.Append(ctx, Record{Kind: "k"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := keyed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	wrongKey, _ := New(store, Config{Key: []byte("other")})
	_, err := wrongKey.Verify(ctx)
	assertBreak(t, err, 0, ErrGenesis)
	unkeyed, _ := New(store, Config{})
	_, err = unkeyed.Verify(ctx)
	assertBreak(t, err, 0, ErrGenesis)

	// Without a genesis entry, a wrong key surfaces as a hash mismatch on the first entry.
	store2 := NewMemoryStore()
	k2, _ := New(store2, Config{Key: []byte("secret"), NoGenesis: true})
	_, _ = k2.Append(ctx, Record{Kind: "k"})
	w2, _ := New(store2, Config{Key: []byte("other"), NoGenesis: true})
	_, err = w2.Verify(ctx)
	assertBreak(t, err, 1, ErrHashMismatch)
}

func TestConfigurableHash(t *testing.T) {
	c, s := newTestChain(t, Config{Hash: crypto.SHA512}, 3)
	if _, err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	h, _ := c.Head(ctx)
	if len(h.Hash) != 64 {
		t.Fatalf("hash len = %d", len(h.Hash))
	}
	sha256Chain, _ := New(s, Config{})
	_, err := sha256Chain.Verify(ctx)
	assertBreak(t, err, 0, ErrGenesis)
}

func TestGenesisBindsName(t *testing.T) {
	_, s := newTestChain(t, Config{Name: "orders"}, 2)
	other, _ := New(s, Config{Name: "payments"})
	_, err := other.Verify(ctx)
	assertBreak(t, err, 0, ErrGenesis)
}

func TestVerifyRange(t *testing.T) {
	c, _ := newTestChain(t, Config{}, 20)
	rep, err := c.VerifyRange(ctx, 5, 9)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 5 || rep.First.Seq != 5 || rep.Last.Seq != 9 {
		t.Fatalf("rep=%+v", rep)
	}
	if _, err := c.VerifyRange(ctx, 0, 20); err != nil {
		t.Fatal(err)
	}
	_, err = c.VerifyRange(ctx, 15, 25)
	assertBreak(t, err, 21, ErrTruncated)
	if _, err := c.VerifyRange(ctx, 9, 5); err == nil {
		t.Fatal("inverted range accepted")
	}
}

func TestVerifyFromCheckpoint(t *testing.T) {
	c, s := newTestChain(t, Config{}, 10)
	cp, _ := c.Head(ctx)
	for i := 0; i < 5; i++ {
		_, _ = c.Append(ctx, Record{Kind: "more"})
	}
	rep, err := c.VerifyFrom(ctx, cp)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != 5 || rep.First.Seq != 11 || rep.Last.Seq != 15 {
		t.Fatalf("rep=%+v", rep)
	}
	// A checkpoint with a different hash at the same seq.
	bad := Checkpoint{Seq: cp.Seq, Hash: bytes.Repeat([]byte{1}, 32)}
	_, err = c.VerifyFrom(ctx, bad)
	assertBreak(t, err, cp.Seq, ErrCheckpointMismatch)
	// A checkpoint beyond the head (truncated chain).
	_, err = c.VerifyFrom(ctx, Checkpoint{Seq: 99, Hash: cp.Hash})
	assertBreak(t, err, 99, ErrTruncated)
	_ = s
}

func TestUnknownVersion(t *testing.T) {
	c, s := newTestChain(t, Config{}, 3)
	s.entries[2].Version = 9
	_, err := c.Verify(ctx)
	assertBreak(t, err, 2, ErrUnknownVersion)
}

// assertBreak checks that err is a *VerifyError at seq with the given reason.
func assertBreak(t *testing.T, err error, seq uint64, reason error) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("want *VerifyError(%v at %d), got %v", reason, seq, err)
	}
	if ve.Seq != seq || !errors.Is(err, reason) {
		t.Fatalf("want %v at seq %d, got: %v", reason, seq, err)
	}
}

func TestConcurrentAppendDoesNotFork(t *testing.T) {
	c, s := newTestChain(t, Config{}, 0)
	const writers, perWriter = 16, 200
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				var err error
				if i%10 == 0 {
					_, err = c.AppendBatch(ctx, Record{Kind: "b"}, Record{Kind: "b"})
				} else {
					_, err = c.Append(ctx, Record{Kind: "w", Payload: []byte{byte(w), byte(i)}})
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	// Concurrent readers.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if _, err := c.Verify(ctx); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	<-done
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	want := 1 + writers*perWriter + writers*(perWriter/10) // genesis + singles + extra batch entries
	if s.Len() != want {
		t.Fatalf("len=%d want %d", s.Len(), want)
	}
	rep, err := c.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Entries != uint64(want) {
		t.Fatalf("verified %d, want %d", rep.Entries, want)
	}
}
