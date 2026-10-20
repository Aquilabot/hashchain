package hashchain

import (
	"testing"
)

var benchPayload = []byte(`{"actor":"3f2a9c","target":"org-1234","action":"member.role_changed","from":"viewer","to":"moderator"}`)

func BenchmarkAppend(b *testing.B) {
	c, _ := newTestChain(b, Config{}, 0)
	rec := Record{Kind: "bench.event", Payload: benchPayload}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Append(ctx, rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendBatch100(b *testing.B) {
	c, _ := newTestChain(b, Config{}, 0)
	recs := make([]Record, 100)
	for i := range recs {
		recs[i] = Record{Kind: "bench.event", Payload: benchPayload}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.AppendBatch(ctx, recs...); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*100), "ns/entry")
}

func benchVerify(b *testing.B, cfg Config) {
	const n = 10_000
	c, _ := newTestChain(b, cfg, 0)
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Kind: "bench.event", Payload: benchPayload}
	}
	if _, err := c.AppendBatch(ctx, recs...); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Verify(ctx); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(n+1)), "ns/entry")
}

func BenchmarkVerify10k(b *testing.B) { benchVerify(b, Config{}) }
func BenchmarkVerify10kHMAC(b *testing.B) {
	benchVerify(b, Config{Key: []byte("0123456789abcdef0123456789abcdef")})
}

func BenchmarkEncodeV1(b *testing.B) {
	e := Entry{Seq: 42, Kind: "bench.event", Payload: benchPayload, PrevHash: make([]byte, 32)}
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for b.Loop() {
		buf, _ = AppendV1(buf[:0], &e)
	}
}
