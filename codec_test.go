package hashchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// Golden vector: pins the v1 encoding. If this test fails, the encoding
// changed and existing chains would stop verifying.
func TestV1GoldenVector(t *testing.T) {
	e := Entry{
		Seq:      7,
		Time:     time.Date(2026, 1, 2, 3, 4, 5, 678901000, time.UTC),
		Kind:     "user.login",
		Payload:  []byte(`{"user":"alice"}`),
		PrevHash: bytes.Repeat([]byte{0xab}, 32),
	}
	b, err := AppendV1(nil, &e)
	if err != nil {
		t.Fatal(err)
	}
	wantPre := "68617368636861696e00" + // "hashchain\x00"
		"01" + // version
		"0000000000000007" + // seq
		"0006475ef6574f35" + // unix micros (1767323045678901)
		"0000000a" + hex.EncodeToString([]byte("user.login")) +
		"00000010" + hex.EncodeToString([]byte(`{"user":"alice"}`)) +
		"20" + hex.EncodeToString(e.PrevHash)
	if got := hex.EncodeToString(b); got != wantPre {
		t.Fatalf("preimage\n got %s\nwant %s", got, wantPre)
	}
	sum := sha256.Sum256(b)
	// Computed independently (Python hashlib) from the preimage above.
	const wantHash = "811faaf92dd91abb1a4579e79acf292cf6f7f3d937cacc8862e507667f185f4c"
	if got := hex.EncodeToString(sum[:]); got != wantHash {
		t.Fatalf("sha256 = %s, want %s", got, wantHash)
	}
}

func TestV1TimeIsMicrosecondUTC(t *testing.T) {
	a := Entry{Time: time.Date(2026, 1, 1, 0, 0, 0, 1000, time.UTC)}
	b := Entry{Time: time.Date(2026, 1, 1, 1, 0, 0, 1999, time.FixedZone("+1", 3600))}
	ea, _ := AppendV1(nil, &a)
	eb, _ := AppendV1(nil, &b)
	if !bytes.Equal(ea, eb) {
		t.Fatal("same instant in different zones / sub-microsecond noise must encode identically")
	}
}

func TestV1RejectsOversizedPrevHash(t *testing.T) {
	if _, err := AppendV1(nil, &Entry{PrevHash: make([]byte, 256)}); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeV1RejectsNonCanonical(t *testing.T) {
	good, _ := AppendV1(nil, &Entry{Seq: 1, Kind: "k", Payload: []byte("p"), PrevHash: []byte{1, 2}})
	if _, err := DecodeV1(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"trailing":  append(bytes.Clone(good), 0),
		"truncated": good[:len(good)-1],
		"tag":       append([]byte("hashchainX"), good[10:]...),
		"version":   append(append(bytes.Clone(good[:10]), 2), good[11:]...),
		"empty":     nil,
	}
	for name, b := range bad {
		if _, err := DecodeV1(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzV1RoundTrip: Decode(Encode(e)) == e for arbitrary fields.
func FuzzV1RoundTrip(f *testing.F) {
	f.Add(uint64(0), int64(0), "k", []byte(nil), []byte(nil))
	f.Add(uint64(1<<63), int64(-1), "user.login", []byte(`{"a":1}`), bytes.Repeat([]byte{9}, 32))
	f.Fuzz(func(t *testing.T, seq uint64, micros int64, kind string, payload, prev []byte) {
		if len(prev) > 255 {
			prev = prev[:255]
		}
		e := Entry{Seq: seq, Time: time.UnixMicro(micros).UTC(), Kind: kind, Payload: payload, PrevHash: prev}
		b, err := AppendV1(nil, &e)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DecodeV1(b)
		if err != nil {
			t.Fatal(err)
		}
		if d.Seq != e.Seq || !d.Time.Equal(e.Time) || d.Kind != e.Kind ||
			!bytes.Equal(d.Payload, e.Payload) || !bytes.Equal(d.PrevHash, e.PrevHash) {
			t.Fatalf("round trip mismatch: %+v vs %+v", d, e)
		}
		// Encoding is a pure function: same input, same bytes, regardless of
		// the destination buffer.
		b2, _ := AppendV1(make([]byte, 3, 64), &e)
		if !bytes.Equal(b, b2[3:]) {
			t.Fatal("encoding depends on dst")
		}
	})
}

// FuzzV1Decode: arbitrary input never panics, and anything accepted is
// canonical (re-encodes to the identical bytes).
func FuzzV1Decode(f *testing.F) {
	good, _ := AppendV1(nil, &Entry{Seq: 3, Kind: "k", Payload: []byte("p"), PrevHash: []byte{1}})
	f.Add(good)
	f.Add([]byte("hashchain\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeV1(b)
		if err != nil {
			return
		}
		re, err := AppendV1(nil, &e)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(re, b) {
			t.Fatalf("non-canonical input accepted:\n in  %x\n out %x", b, re)
		}
	})
}
