package hashchain

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"math"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	_ "crypto/sha256" // register SHA-256, the default hash
)

// GenesisKind is the Kind of the genesis entry written at Seq 0.
const GenesisKind = "hashchain.genesis"

// Config configures a Chain. The zero value is valid: SHA-256, unkeyed,
// v1 encoding, with a genesis entry.
type Config struct {
	// Hash is the digest function. Zero means crypto.SHA256. The function
	// must be linked into the binary (import its package, e.g. crypto/sha512).
	Hash crypto.Hash

	// Key, when non-empty, turns the chain into a keyed chain: every digest
	// is HMAC(Key, preimage) instead of Hash(preimage). Without the key
	// nobody can forge or verify entries.
	Key []byte

	// Codec encodes new entries. Zero means V1Codec.
	Codec Codec

	// ExtraCodecs are additional codecs accepted during verification, for
	// chains that contain entries from older encodings.
	ExtraCodecs []Codec

	// NoGenesis disables the genesis entry: the first application entry
	// gets Seq 1 and an empty PrevHash. Use it only for chains created
	// without one (for example, pre-existing legacy chains); a genesis
	// entry binds the chain to its hash configuration and Name.
	NoGenesis bool

	// Name is committed to by the genesis entry. Two chains with different
	// names cannot have their entries spliced into each other even when
	// they share a key.
	Name string

	// Now returns the current time. Zero means time.Now.
	Now func() time.Time
}

// Chain appends and verifies entries of one hash chain stored in a Store.
// A Chain is safe for concurrent use; fork-freedom across processes is the
// Store's responsibility (see Store.Append).
type Chain struct {
	store       Store
	hash        crypto.Hash
	key         []byte
	codec       Codec
	codecs      map[uint8]Codec
	genesis     bool
	genesisData []byte
	now         func() time.Time
	pool        sync.Pool // *digester
}

// New returns a Chain over store.
func New(store Store, cfg Config) (*Chain, error) {
	if store == nil {
		return nil, errors.New("hashchain: nil store")
	}
	h := cfg.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	if !h.Available() {
		return nil, fmt.Errorf("hashchain: hash function %v is not linked into the binary", h)
	}
	if h.Size() > math.MaxUint8 {
		return nil, fmt.Errorf("hashchain: digest size %d exceeds 255 bytes", h.Size())
	}
	codec := cfg.Codec
	if codec == nil {
		codec = V1Codec{}
	}
	c := &Chain{
		store:   store,
		hash:    h,
		key:     bytes.Clone(cfg.Key),
		codec:   codec,
		codecs:  map[uint8]Codec{V1: V1Codec{}},
		genesis: !cfg.NoGenesis,
		now:     cfg.Now,
	}
	for _, x := range cfg.ExtraCodecs {
		c.codecs[x.Version()] = x
	}
	c.codecs[codec.Version()] = codec
	if c.now == nil {
		c.now = time.Now
	}
	c.genesisData = genesisPayload(h, len(c.key) > 0, codec.Version(), cfg.Name)
	c.pool.New = func() any { return c.newDigester() }
	return c, nil
}

// genesisPayload is the canonical description committed to by the genesis
// entry: newline-separated key=value pairs in fixed order.
func genesisPayload(h crypto.Hash, keyed bool, codec uint8, name string) []byte {
	var b []byte
	b = append(b, "hashchain-genesis/1\nhash="...)
	b = append(b, h.String()...)
	b = append(b, "\nkeyed="...)
	b = strconv.AppendBool(b, keyed)
	b = append(b, "\ncodec="...)
	b = strconv.AppendUint(b, uint64(codec), 10)
	b = append(b, "\nname="...)
	b = strconv.AppendQuote(b, name)
	return b
}

// digester bundles a reusable hash state and buffers.
type digester struct {
	h   hash.Hash
	buf []byte
	sum []byte
}

func (c *Chain) newDigester() *digester {
	var h hash.Hash
	if len(c.key) > 0 {
		h = hmac.New(c.hash.New, c.key)
	} else {
		h = c.hash.New()
	}
	return &digester{h: h, buf: make([]byte, 0, 512), sum: make([]byte, 0, h.Size())}
}

func (d *digester) digest(preimage []byte) []byte {
	d.h.Reset()
	d.h.Write(preimage)
	d.sum = d.h.Sum(d.sum[:0])
	return d.sum
}

func (c *Chain) codecFor(v uint8) (Codec, bool) {
	codec, ok := c.codecs[v]
	return codec, ok
}

// hashEntry returns a freshly allocated digest of e.
func (c *Chain) hashEntry(d *digester, e *Entry) ([]byte, error) {
	codec, ok := c.codecFor(e.Version)
	if !ok {
		return nil, ErrUnknownVersion
	}
	var err error
	d.buf, err = codec.AppendPreimage(d.buf[:0], e)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(d.digest(d.buf)), nil
}

// checkHash recomputes e's digest and compares it with e.Hash in constant
// time. It returns the recomputed digest when it differs.
func (c *Chain) checkHash(d *digester, e *Entry) (ok bool, got []byte, err error) {
	codec, found := c.codecFor(e.Version)
	if !found {
		return false, nil, ErrUnknownVersion
	}
	if m, isMatcher := codec.(HashMatcher); isMatcher {
		ok, err := m.MatchHash(e, d.digest)
		return ok, nil, err
	}
	d.buf, err = codec.AppendPreimage(d.buf[:0], e)
	if err != nil {
		return false, nil, err
	}
	sum := d.digest(d.buf)
	if subtle.ConstantTimeCompare(sum, e.Hash) == 1 {
		return true, nil, nil
	}
	return false, bytes.Clone(sum), nil
}

func validateKind(kind string) error {
	switch {
	case kind == "":
		return errors.New("hashchain: empty kind")
	case !utf8.ValidString(kind):
		return errors.New("hashchain: kind is not valid UTF-8")
	case bytes.IndexByte([]byte(kind), 0) >= 0:
		return errors.New("hashchain: kind contains a NUL byte")
	}
	return nil
}

// Append adds one record to the chain and returns the stored entry.
func (c *Chain) Append(ctx context.Context, rec Record) (Entry, error) {
	out, err := c.AppendBatch(ctx, rec)
	if err != nil {
		return Entry{}, err
	}
	return out[0], nil
}

// AppendBatch adds records atomically, in order, under a single store
// transaction. It is much cheaper per record than repeated Append calls on
// stores with per-transaction overhead.
func (c *Chain) AppendBatch(ctx context.Context, recs ...Record) ([]Entry, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	for i := range recs {
		if err := validateKind(recs[i].Kind); err != nil {
			return nil, err
		}
	}
	now := c.now().UTC().Truncate(time.Microsecond)
	var result []Entry
	err := c.store.Append(ctx, func(head *Entry) ([]Entry, error) {
		d := c.pool.Get().(*digester)
		defer c.pool.Put(d)
		out := make([]Entry, 0, len(recs)+1)
		var seq uint64
		var prev []byte
		switch {
		case head != nil:
			if head.Seq == math.MaxInt64 {
				return nil, errors.New("hashchain: sequence space exhausted")
			}
			seq, prev = head.Seq+1, head.Hash
		case c.genesis:
			g := Entry{Seq: 0, Version: c.codec.Version(), Time: now, Kind: GenesisKind, Payload: c.genesisData}
			h, err := c.hashEntry(d, &g)
			if err != nil {
				return nil, err
			}
			g.Hash = h
			out = append(out, g)
			seq, prev = 1, h
		default:
			seq = 1
		}
		for i := range recs {
			t := now
			if !recs[i].Time.IsZero() {
				t = recs[i].Time.UTC().Truncate(time.Microsecond)
			}
			e := Entry{
				Seq:      seq,
				Version:  c.codec.Version(),
				Time:     t,
				Kind:     recs[i].Kind,
				Payload:  recs[i].Payload,
				PrevHash: prev,
			}
			h, err := c.hashEntry(d, &e)
			if err != nil {
				return nil, err
			}
			e.Hash = h
			out = append(out, e)
			seq, prev = seq+1, h
		}
		result = out
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	if c.genesis && len(result) > len(recs) {
		result = result[1:]
	}
	for i := range result {
		result[i].PrevHash = bytes.Clone(result[i].PrevHash)
		result[i].Payload = bytes.Clone(result[i].Payload)
	}
	return result, nil
}

// Head returns the checkpoint of the last entry without verifying anything.
// The zero Checkpoint means the chain is empty.
func (c *Chain) Head(ctx context.Context) (Checkpoint, error) {
	h, err := c.store.Head(ctx)
	if err != nil || h == nil {
		return Checkpoint{}, err
	}
	return Checkpoint{Seq: h.Seq, Hash: bytes.Clone(h.Hash)}, nil
}

func (c *Chain) firstSeq() uint64 {
	if c.genesis {
		return 0
	}
	return 1
}

// Verify checks every entry from the start of the chain to the head that
// exists when Verify starts. It streams entries from the store and keeps
// O(1) memory.
//
// Verify cannot detect that entries were removed from the end of the chain,
// or that the whole chain was rewritten; compare the returned Last checkpoint
// with an externally anchored one, or use VerifyFrom.
func (c *Chain) Verify(ctx context.Context) (Report, error) {
	head, err := c.store.Head(ctx)
	if err != nil {
		return Report{}, err
	}
	if head == nil {
		return Report{}, nil
	}
	return c.verify(ctx, c.firstSeq(), head.Seq, nil)
}

// VerifyRange checks entries from..to (inclusive). Entry from-1, if any, is
// used as the trusted predecessor: its hash is not recomputed but entry
// from must link to it. When from is the first sequence number of the chain
// the genesis rules are checked instead. Missing entries up to to are
// reported as ErrTruncated.
func (c *Chain) VerifyRange(ctx context.Context, from, to uint64) (Report, error) {
	if from > to {
		return Report{}, fmt.Errorf("hashchain: invalid range %d..%d", from, to)
	}
	if from <= c.firstSeq() {
		return c.verify(ctx, c.firstSeq(), to, nil)
	}
	return c.verify(ctx, from, to, &Checkpoint{Seq: from - 1})
}

// VerifyFrom verifies the chain from a trusted checkpoint (for example one
// previously published to an external anchor) up to the current head. It
// fails with ErrCheckpointMismatch if the stored entry at cp.Seq does not
// have cp.Hash, and with ErrTruncated if the chain no longer reaches cp.Seq.
// The zero Checkpoint verifies the whole chain.
func (c *Chain) VerifyFrom(ctx context.Context, cp Checkpoint) (Report, error) {
	if cp.IsZero() {
		return c.Verify(ctx)
	}
	head, err := c.store.Head(ctx)
	if err != nil {
		return Report{}, err
	}
	if head == nil || head.Seq < cp.Seq {
		var got uint64
		if head != nil {
			got = head.Seq
		}
		return Report{}, &VerifyError{Seq: cp.Seq, Reason: ErrTruncated,
			Detail: fmt.Sprintf("head is at seq %d, checkpoint at seq %d", got, cp.Seq)}
	}
	anchor := cp
	return c.verify(ctx, cp.Seq, head.Seq, &anchor)
}

// verify scans [from, to]. When anchor is non-nil, the entry at anchor.Seq
// (== from or from-1) is the trusted predecessor: if anchor.Hash is set it
// must match the stored hash, otherwise the stored hash is trusted.
func (c *Chain) verify(ctx context.Context, from, to uint64, anchor *Checkpoint) (Report, error) {
	d := c.pool.Get().(*digester)
	defer c.pool.Put(d)

	var (
		rep      Report
		started  = anchor == nil
		expected = from // next sequence number we expect to see
		prevHash = make([]byte, 0, c.hash.Size())
	)
	scanFrom := from
	if anchor != nil {
		scanFrom = anchor.Seq
		expected = anchor.Seq
	}

	err := c.store.Scan(ctx, scanFrom, to, func(e *Entry) error {
		if e.Seq != expected {
			reason := ErrSequence
			switch {
			case !started:
				reason = ErrTruncated
			case expected == 0 && c.genesis:
				reason = ErrGenesis
			}
			return &VerifyError{Seq: expected, Reason: reason,
				Detail: fmt.Sprintf("expected seq %d, found seq %d", expected, e.Seq)}
		}
		if !started {
			// e is the trusted predecessor.
			if len(anchor.Hash) > 0 && !bytes.Equal(anchor.Hash, e.Hash) {
				return &VerifyError{Seq: e.Seq, Reason: ErrCheckpointMismatch,
					Expected: bytes.Clone(anchor.Hash), Actual: bytes.Clone(e.Hash)}
			}
			prevHash = append(prevHash[:0], e.Hash...)
			started = true
			expected++
			return nil
		}
		if e.Seq == c.firstSeq() {
			if err := c.checkGenesisShape(e); err != nil {
				return err
			}
		} else if !bytes.Equal(e.PrevHash, prevHash) {
			return &VerifyError{Seq: e.Seq, Reason: ErrBrokenLink,
				Expected: bytes.Clone(prevHash), Actual: bytes.Clone(e.PrevHash)}
		}
		ok, got, err := c.checkHash(d, e)
		switch {
		case errors.Is(err, ErrUnknownVersion):
			return &VerifyError{Seq: e.Seq, Reason: ErrUnknownVersion, Detail: fmt.Sprintf("version %d", e.Version)}
		case err != nil:
			return &VerifyError{Seq: e.Seq, Reason: ErrEncoding, Err: err}
		case !ok:
			reason := ErrHashMismatch
			if e.Seq == 0 && c.genesis {
				reason = ErrGenesis
			}
			return &VerifyError{Seq: e.Seq, Reason: reason, Expected: got, Actual: bytes.Clone(e.Hash)}
		}
		if rep.Entries == 0 {
			rep.First = Checkpoint{Seq: e.Seq, Hash: bytes.Clone(e.Hash)}
		}
		rep.Entries++
		prevHash = append(prevHash[:0], e.Hash...)
		expected++
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	if !started || expected <= to {
		return Report{}, &VerifyError{Seq: expected, Reason: ErrTruncated,
			Detail: fmt.Sprintf("store ends before seq %d", to)}
	}
	rep.Last = Checkpoint{Seq: expected - 1, Hash: bytes.Clone(prevHash)}
	return rep, nil
}

// checkGenesisShape validates the first entry of the chain (everything but
// its hash, which the caller checks next).
func (c *Chain) checkGenesisShape(e *Entry) error {
	if len(e.PrevHash) != 0 {
		return &VerifyError{Seq: e.Seq, Reason: ErrGenesis, Detail: "first entry has a non-empty prev hash",
			Actual: bytes.Clone(e.PrevHash)}
	}
	if !c.genesis {
		return nil
	}
	if e.Kind != GenesisKind || !bytes.Equal(e.Payload, c.genesisData) {
		return &VerifyError{Seq: e.Seq, Reason: ErrGenesis,
			Detail: fmt.Sprintf("genesis does not match this chain's configuration (kind %q)", e.Kind)}
	}
	return nil
}
