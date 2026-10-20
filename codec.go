package hashchain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Codec produces the byte string ("preimage") that is hashed for an entry.
// Each codec owns one Entry.Version value, so a chain can hold entries
// written with different encodings and still verify all of them.
type Codec interface {
	// Version is the Entry.Version this codec handles.
	Version() uint8
	// AppendPreimage appends the canonical encoding of e to dst. It must not
	// read e.Hash. The result must be a pure function of the other fields.
	AppendPreimage(dst []byte, e *Entry) ([]byte, error)
}

// HashMatcher is an optional interface for codecs whose stored form cannot
// always reproduce the exact preimage, for example a legacy format that
// hashed nanosecond timestamps but persisted microseconds. When a codec
// implements it, verification calls MatchHash instead of comparing
// sum(AppendPreimage(e)) with e.Hash.
//
// sum hashes a preimage with the chain's configured hash (and key) and
// returns a digest that is only valid until the next call.
type HashMatcher interface {
	MatchHash(e *Entry, sum func(preimage []byte) []byte) (bool, error)
}

// V1 is the version number of the canonical binary encoding.
const V1 uint8 = 1

// domainTag prefixes every v1 preimage so that a v1 digest can never collide
// with a digest of some other structure hashed with the same key.
const domainTag = "hashchain\x00"

const v1FixedLen = len(domainTag) + 1 + 8 + 8 + 4 + 4 + 1

// Encoding errors.
var (
	ErrKindTooLong     = errors.New("hashchain: kind longer than 2^32-1 bytes")
	ErrPayloadTooLong  = errors.New("hashchain: payload longer than 2^32-1 bytes")
	ErrPrevHashTooLong = errors.New("hashchain: prev hash longer than 255 bytes")
	ErrMalformed       = errors.New("hashchain: malformed v1 encoding")
)

// V1Codec is the canonical length-prefixed binary encoding (version 1):
//
//	"hashchain" 0x00          10 bytes, domain separation tag
//	version                    1 byte, 0x01
//	seq                        8 bytes, uint64 big-endian
//	time                       8 bytes, int64 big-endian, Unix microseconds (UTC)
//	len(kind)                  4 bytes, uint32 big-endian
//	kind                       len(kind) bytes, UTF-8
//	len(payload)               4 bytes, uint32 big-endian
//	payload                    len(payload) bytes
//	len(prev_hash)             1 byte
//	prev_hash                  len(prev_hash) bytes
//
// Every field has exactly one representation, so equal entries always encode
// to equal bytes and DecodeV1 accepts only canonical input.
type V1Codec struct{}

// Version implements Codec.
func (V1Codec) Version() uint8 { return V1 }

// AppendPreimage implements Codec.
func (V1Codec) AppendPreimage(dst []byte, e *Entry) ([]byte, error) {
	return AppendV1(dst, e)
}

// AppendV1 appends the v1 encoding of e (ignoring e.Hash and e.Version) to dst.
func AppendV1(dst []byte, e *Entry) ([]byte, error) {
	if uint64(len(e.Kind)) > math.MaxUint32 {
		return dst, ErrKindTooLong
	}
	if uint64(len(e.Payload)) > math.MaxUint32 {
		return dst, ErrPayloadTooLong
	}
	if len(e.PrevHash) > math.MaxUint8 {
		return dst, ErrPrevHashTooLong
	}
	n := v1FixedLen + len(e.Kind) + len(e.Payload) + len(e.PrevHash)
	if cap(dst)-len(dst) < n {
		grown := make([]byte, len(dst), len(dst)+n)
		copy(grown, dst)
		dst = grown
	}
	dst = append(dst, domainTag...)
	dst = append(dst, V1)
	dst = binary.BigEndian.AppendUint64(dst, e.Seq)
	dst = binary.BigEndian.AppendUint64(dst, uint64(e.Time.UnixMicro()))
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(e.Kind)))
	dst = append(dst, e.Kind...)
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(e.Payload)))
	dst = append(dst, e.Payload...)
	dst = append(dst, byte(len(e.PrevHash)))
	dst = append(dst, e.PrevHash...)
	return dst, nil
}

// DecodeV1 parses a v1 preimage. It rejects anything that AppendV1 would
// not produce, including trailing bytes. Slices in the result alias b.
// Decoded times are in UTC.
func DecodeV1(b []byte) (Entry, error) {
	var e Entry
	if len(b) < v1FixedLen || string(b[:len(domainTag)]) != domainTag {
		return e, ErrMalformed
	}
	b = b[len(domainTag):]
	if b[0] != V1 {
		return e, fmt.Errorf("%w: version %d", ErrMalformed, b[0])
	}
	e.Version = V1
	e.Seq = binary.BigEndian.Uint64(b[1:9])
	e.Time = time.UnixMicro(int64(binary.BigEndian.Uint64(b[9:17]))).UTC()
	b = b[17:]

	take := func(n uint64) ([]byte, bool) {
		if uint64(len(b)) < n {
			return nil, false
		}
		v := b[:n:n]
		b = b[n:]
		return v, true
	}
	lenField, ok := take(4)
	if !ok {
		return e, ErrMalformed
	}
	kind, ok := take(uint64(binary.BigEndian.Uint32(lenField)))
	if !ok {
		return e, ErrMalformed
	}
	e.Kind = string(kind)
	if lenField, ok = take(4); !ok {
		return e, ErrMalformed
	}
	if e.Payload, ok = take(uint64(binary.BigEndian.Uint32(lenField))); !ok {
		return e, ErrMalformed
	}
	if lenField, ok = take(1); !ok {
		return e, ErrMalformed
	}
	if e.PrevHash, ok = take(uint64(lenField[0])); !ok {
		return e, ErrMalformed
	}
	if len(b) != 0 {
		return e, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(b))
	}
	return e, nil
}
