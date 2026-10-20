package pgstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/lib/pq"

	"github.com/Aquilabot/hashchain"
	"github.com/Aquilabot/hashchain/pgstore"
)

// Integration tests need a Postgres. Set HASHCHAIN_TEST_DSN to use an
// existing server; otherwise TestMain starts postgres:17-alpine with Docker.
// Without either, every test in this file is skipped.

var (
	testDSN    string
	skipReason string
	chainSeq   atomic.Int64
)

func TestMain(m *testing.M) {
	cleanup := setupPostgres()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupPostgres() func() {
	if dsn := os.Getenv("HASHCHAIN_TEST_DSN"); dsn != "" {
		testDSN = dsn
		return func() {}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		skipReason = "docker not found and HASHCHAIN_TEST_DSN not set"
		return func() {}
	}
	image := os.Getenv("HASHCHAIN_TEST_IMAGE")
	if image == "" {
		image = "postgres:17-alpine"
	}
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"-e", "POSTGRES_PASSWORD=hashchain", "-e", "POSTGRES_DB=hashchain",
		"-p", "127.0.0.1::5432", image,
		"-c", "max_connections=200").Output()
	if err != nil {
		skipReason = fmt.Sprintf("docker run failed: %v", err)
		return func() {}
	}
	id := strings.TrimSpace(string(out))
	stop := func() { _ = exec.Command("docker", "rm", "-f", id).Run() }
	portOut, err := exec.Command("docker", "port", id, "5432/tcp").Output()
	if err != nil {
		stop()
		skipReason = fmt.Sprintf("docker port failed: %v", err)
		return func() {}
	}
	hostPort := strings.TrimSpace(strings.Split(string(portOut), "\n")[0])
	testDSN = "postgres://postgres:hashchain@" + hostPort + "/hashchain?sslmode=disable"
	deadline := time.Now().Add(60 * time.Second)
	for {
		db, err := sql.Open("pgx", testDSN)
		if err == nil {
			err = db.Ping()
			if err == nil {
				_, err = db.Exec("SELECT 1")
			}
			db.Close()
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			stop()
			skipReason = fmt.Sprintf("postgres did not become ready: %v", err)
			testDSN = ""
			return func() {}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return stop
}

func openDB(tb testing.TB, driver string) *sql.DB {
	tb.Helper()
	if testDSN == "" {
		tb.Skip(skipReason)
	}
	db, err := sql.Open(driver, testDSN)
	if err != nil {
		tb.Fatal(err)
	}
	db.SetMaxOpenConns(32)
	tb.Cleanup(func() { db.Close() })
	if err := pgstore.Migrate(context.Background(), db); err != nil {
		tb.Fatal(err)
	}
	return db
}

func uniqueChain(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), chainSeq.Add(1))
}

func newChain(tb testing.TB, db *sql.DB, cfg hashchain.Config, opts ...pgstore.Option) (*hashchain.Chain, *pgstore.Store, string) {
	tb.Helper()
	name := uniqueChain(tb.Name())
	s, err := pgstore.New(db, name, opts...)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := hashchain.New(s, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	return c, s, name
}

var ctx = context.Background()

func TestAppendVerifyBothDrivers(t *testing.T) {
	for _, driver := range []string{"pgx", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			db := openDB(t, driver)
			c, _, _ := newChain(t, db, hashchain.Config{Key: []byte("k")})
			var last hashchain.Entry
			for i := 0; i < 25; i++ {
				e, err := c.Append(ctx, hashchain.Record{
					Kind:    "test",
					Payload: []byte(fmt.Sprintf("%d", i)),
					Time:    time.Date(2026, 3, 1, 0, 0, 0, 123456789, time.UTC), // sub-µs is dropped
				})
				if err != nil {
					t.Fatal(err)
				}
				last = e
			}
			rep, err := c.Verify(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Entries != 26 || rep.Last.Seq != 25 || !bytes.Equal(rep.Last.Hash, last.Hash) {
				t.Fatalf("rep=%+v", rep)
			}
		})
	}
}

func TestEmptyPayloadAndBatchAcrossChunks(t *testing.T) {
	db := openDB(t, "pgx")
	c, _, _ := newChain(t, db, hashchain.Config{})
	recs := make([]hashchain.Record, 1203) // > 2 insert chunks
	for i := range recs {
		recs[i] = hashchain.Record{Kind: "batch"}
	}
	out, err := c.AppendBatch(ctx, recs...)
	if err != nil {
		t.Fatal(err)
	}
	if out[len(out)-1].Seq != 1203 {
		t.Fatalf("last seq %d", out[len(out)-1].Seq)
	}
	if _, err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPaginationAndRange(t *testing.T) {
	db := openDB(t, "pgx")
	c, _, _ := newChain(t, db, hashchain.Config{}, pgstore.WithPageSize(7))
	for i := 0; i < 50; i++ {
		if _, err := c.Append(ctx, hashchain.Record{Kind: "p"}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := c.Verify(ctx)
	if err != nil || rep.Entries != 51 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
	rep, err = c.VerifyRange(ctx, 13, 29)
	if err != nil || rep.Entries != 17 {
		t.Fatalf("range rep=%+v err=%v", rep, err)
	}
}

// Many writers on separate connection pools (simulating separate processes)
// append to the same chain. The advisory lock must serialize them so that no
// append fails and the chain verifies end to end with no gaps.
func TestConcurrentAppendAcrossPools(t *testing.T) {
	const pools, writersPerPool, perWriter = 4, 8, 25
	name := uniqueChain("concurrent")
	var chains []*hashchain.Chain
	for p := 0; p < pools; p++ {
		db := openDB(t, "pgx")
		s, err := pgstore.New(db, name)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := hashchain.New(s, hashchain.Config{})
		chains = append(chains, c)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, pools*writersPerPool)
	for p := 0; p < pools; p++ {
		for w := 0; w < writersPerPool; w++ {
			wg.Add(1)
			go func(c *hashchain.Chain, id int) {
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					if _, err := c.Append(ctx, hashchain.Record{Kind: "w", Payload: []byte(fmt.Sprint(id, i))}); err != nil {
						errCh <- err
						return
					}
				}
			}(chains[p], p*writersPerPool+w)
		}
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	rep, err := chains[0].Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(1 + pools*writersPerPool*perWriter)
	if rep.Entries != want {
		t.Fatalf("verified %d entries, want %d", rep.Entries, want)
	}
}

func TestAppendOnlyTrigger(t *testing.T) {
	db := openDB(t, "pgx")
	c, _, name := newChain(t, db, hashchain.Config{})
	if _, err := c.Append(ctx, hashchain.Record{Kind: "x"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"UPDATE hashchain_entries SET kind = 'y' WHERE chain = $1",
		"DELETE FROM hashchain_entries WHERE chain = $1",
	} {
		if _, err := db.Exec(q, name); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: expected append-only error, got %v", q, err)
		}
	}
}

// Tampering through SQL by someone who can disable the trigger (the table
// owner) is detected by Verify and pinpointed.
func TestTamperViaSQL(t *testing.T) {
	db := openDB(t, "pgx")
	cases := []struct {
		name   string
		sql    []string
		seq    uint64
		reason error
	}{
		{"edit payload", []string{"UPDATE hashchain_entries SET payload = 'evil' WHERE chain = $1 AND seq = 4"}, 4, hashchain.ErrHashMismatch},
		{"edit time", []string{"UPDATE hashchain_entries SET ts = ts + interval '1 microsecond' WHERE chain = $1 AND seq = 4"}, 4, hashchain.ErrHashMismatch},
		{"delete", []string{"DELETE FROM hashchain_entries WHERE chain = $1 AND seq = 4"}, 4, hashchain.ErrSequence},
		{"reorder", []string{
			"UPDATE hashchain_entries SET seq = 1000 WHERE chain = $1 AND seq = 4",
			"UPDATE hashchain_entries SET seq = 4 WHERE chain = $1 AND seq = 5",
			"UPDATE hashchain_entries SET seq = 5 WHERE chain = $1 AND seq = 1000",
		}, 4, hashchain.ErrBrokenLink},
		{"insert", []string{
			"UPDATE hashchain_entries SET seq = seq + 1000 WHERE chain = $1 AND seq >= 5",
			"UPDATE hashchain_entries SET seq = seq - 999 WHERE chain = $1 AND seq >= 1000",
			"INSERT INTO hashchain_entries SELECT chain, 5, version, ts, 'forged', payload, hash, sha256(hash) FROM hashchain_entries WHERE chain = $1 AND seq = 4",
		}, 5, hashchain.ErrHashMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, name := newChain(t, db, hashchain.Config{})
			for i := 0; i < 8; i++ {
				if _, err := c.Append(ctx, hashchain.Record{Kind: "e", Payload: []byte{byte(i)}}); err != nil {
					t.Fatal(err)
				}
			}
			tamper(t, db, name, tc.sql...)
			_, err := c.Verify(ctx)
			var ve *hashchain.VerifyError
			if !errors.As(err, &ve) || ve.Seq != tc.seq || !errors.Is(err, tc.reason) {
				t.Fatalf("want %v at %d, got %v", tc.reason, tc.seq, err)
			}
		})
	}
	t.Run("truncate tail needs anchor", func(t *testing.T) {
		c, _, name := newChain(t, db, hashchain.Config{})
		for i := 0; i < 8; i++ {
			_, _ = c.Append(ctx, hashchain.Record{Kind: "e"})
		}
		anchor, _ := c.Head(ctx)
		tamper(t, db, name, "DELETE FROM hashchain_entries WHERE chain = $1 AND seq > 5")
		if _, err := c.Verify(ctx); err != nil {
			t.Fatalf("plain verify should pass on a truncated chain, got %v", err)
		}
		if _, err := c.VerifyFrom(ctx, anchor); !errors.Is(err, hashchain.ErrTruncated) {
			t.Fatalf("want ErrTruncated, got %v", err)
		}
	})
}

func tamper(t *testing.T, db *sql.DB, chain string, stmts ...string) {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// ALTER TABLE takes an ACCESS EXCLUSIVE lock and is transactional, so the
	// trigger is only disabled for this transaction's statements.
	if _, err := tx.Exec("ALTER TABLE hashchain_entries DISABLE TRIGGER hashchain_entries_append_only"); err != nil {
		t.Fatal(err)
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q, chain); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("ALTER TABLE hashchain_entries ENABLE TRIGGER hashchain_entries_append_only"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateCustomTableAndIdempotent(t *testing.T) {
	db := openDB(t, "pgx")
	for i := 0; i < 2; i++ {
		if err := pgstore.Migrate(ctx, db, pgstore.WithTable("audit_chain")); err != nil {
			t.Fatal(err)
		}
	}
	c, _, _ := newChain(t, db, hashchain.Config{}, pgstore.WithTable("audit_chain"))
	if _, err := c.Append(ctx, hashchain.Record{Kind: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pgstore.New(db, "c", pgstore.WithTable("bad; drop table x")); err == nil {
		t.Fatal("invalid table name accepted")
	}
}

func TestChainsAreIsolated(t *testing.T) {
	db := openDB(t, "pgx")
	a, _, _ := newChain(t, db, hashchain.Config{})
	b, _, _ := newChain(t, db, hashchain.Config{})
	for i := 0; i < 3; i++ {
		_, _ = a.Append(ctx, hashchain.Record{Kind: "a"})
	}
	_, _ = b.Append(ctx, hashchain.Record{Kind: "b"})
	ra, err := a.Verify(ctx)
	if err != nil || ra.Last.Seq != 3 {
		t.Fatalf("a: %+v %v", ra, err)
	}
	rb, err := b.Verify(ctx)
	if err != nil || rb.Last.Seq != 1 {
		t.Fatalf("b: %+v %v", rb, err)
	}
}

var benchPayload = []byte(`{"actor":"3f2a9c","target":"org-1234","action":"member.role_changed","from":"viewer","to":"moderator"}`)

func BenchmarkPGAppend(b *testing.B) {
	db := openDB(b, "pgx")
	c, _, _ := newChain(b, db, hashchain.Config{})
	rec := hashchain.Record{Kind: "bench.event", Payload: benchPayload}
	for b.Loop() {
		if _, err := c.Append(ctx, rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPGAppendParallel(b *testing.B) {
	db := openDB(b, "pgx")
	c, _, _ := newChain(b, db, hashchain.Config{})
	rec := hashchain.Record{Kind: "bench.event", Payload: benchPayload}
	b.SetParallelism(4) // 4 x GOMAXPROCS writers contending for one chain
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := c.Append(ctx, rec); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkPGAppendBatch100(b *testing.B) {
	db := openDB(b, "pgx")
	c, _, _ := newChain(b, db, hashchain.Config{})
	recs := make([]hashchain.Record, 100)
	for i := range recs {
		recs[i] = hashchain.Record{Kind: "bench.event", Payload: benchPayload}
	}
	for b.Loop() {
		if _, err := c.AppendBatch(ctx, recs...); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*100), "ns/entry")
}

func BenchmarkPGVerify10k(b *testing.B) {
	const n = 10_000
	db := openDB(b, "pgx")
	c, _, _ := newChain(b, db, hashchain.Config{})
	recs := make([]hashchain.Record, n)
	for i := range recs {
		recs[i] = hashchain.Record{Kind: "bench.event", Payload: benchPayload}
	}
	if _, err := c.AppendBatch(ctx, recs...); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Verify(ctx); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(n+1)), "ns/entry")
}
