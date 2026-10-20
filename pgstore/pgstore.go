// Package pgstore is a PostgreSQL implementation of hashchain.Store built on
// database/sql. It works with any driver that speaks the Postgres protocol,
// such as github.com/jackc/pgx/v5/stdlib or github.com/lib/pq.
//
// # Concurrency
//
// Append runs in a READ COMMITTED transaction that first takes a
// transaction-scoped advisory lock, pg_advisory_xact_lock(key), where key is
// derived from the table and chain names (see LockKey). Only then does it
// read the head and insert the new entries. Writers on the same chain are
// therefore serialized across every connection and process, and the lock is
// released automatically at COMMIT or ROLLBACK. Because the lock is
// transaction-scoped it works behind PgBouncer in transaction pooling mode.
// The (chain, seq) primary key is a second line of defense: two entries can
// never share a sequence number, so the chain cannot fork even if a writer
// bypasses the lock.
//
// READ COMMITTED matters: each statement takes a fresh snapshot, so the head
// query sees the previous writer's commit. Under REPEATABLE READ the snapshot
// would predate the lock and the insert would fail on the primary key.
package pgstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Aquilabot/hashchain"
)

//go:embed migrations/0001_hashchain_entries.sql
var migrationV1 string

// DefaultTable is the table used when WithTable is not given.
const DefaultTable = "hashchain_entries"

const insertChunk = 500 // rows per INSERT statement (8 params each)

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,40}$`)

type options struct {
	table    string
	pageSize int
}

// Option configures a Store or Migrate.
type Option func(*options)

// WithTable sets the table name. It must match ^[a-z_][a-z0-9_]{0,40}$.
func WithTable(name string) Option { return func(o *options) { o.table = name } }

// WithPageSize sets how many rows Scan fetches per query (default 1000).
func WithPageSize(n int) Option { return func(o *options) { o.pageSize = n } }

func buildOptions(opts []Option) (options, error) {
	o := options{table: DefaultTable, pageSize: 1000}
	for _, f := range opts {
		f(&o)
	}
	if !identRe.MatchString(o.table) {
		return o, fmt.Errorf("pgstore: invalid table name %q", o.table)
	}
	if o.pageSize <= 0 {
		return o, errors.New("pgstore: page size must be positive")
	}
	return o, nil
}

// MigrationSQL returns the schema DDL for the given table name. The SQL is
// idempotent; use it with your own migration tool or call Migrate.
func MigrationSQL(opts ...Option) (string, error) {
	o, err := buildOptions(opts)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(migrationV1, DefaultTable, o.table), nil
}

// Migrate creates the table, the append-only trigger and its function if
// they do not exist.
func Migrate(ctx context.Context, db *sql.DB, opts ...Option) error {
	ddl, err := MigrationSQL(opts...)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, ddl)
	return err
}

// Store stores one chain in a Postgres table.
type Store struct {
	db       *sql.DB
	chain    string
	table    string
	pageSize int
	lockKey  int64

	qHead, qScan, qInsert1 string
}

var _ hashchain.Store = (*Store)(nil)

// New returns a Store for the chain named chain. The table must exist (see
// Migrate).
func New(db *sql.DB, chain string, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("pgstore: nil db")
	}
	if chain == "" {
		return nil, errors.New("pgstore: empty chain name")
	}
	o, err := buildOptions(opts)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, chain: chain, table: o.table, pageSize: o.pageSize, lockKey: LockKey(o.table, chain)}
	cols := "seq, version, ts, kind, payload, prev_hash, hash"
	s.qHead = "SELECT seq, hash FROM " + s.table + " WHERE chain = $1 ORDER BY seq DESC LIMIT 1"
	s.qScan = "SELECT " + cols + " FROM " + s.table +
		" WHERE chain = $1 AND seq >= $2 AND seq <= $3 ORDER BY seq LIMIT $4"
	s.qInsert1 = insertSQL(s.table, 1)
	return s, nil
}

// LockKey is the advisory lock key used by Append for (table, chain): the
// FNV-1a 64-bit hash of "hashchain\x00" + table + "\x00" + chain, as a
// signed bigint. It is exported so operators can inspect pg_locks.
func LockKey(table, chain string) int64 {
	h := fnv.New64a()
	h.Write([]byte("hashchain\x00"))
	h.Write([]byte(table))
	h.Write([]byte{0})
	h.Write([]byte(chain))
	return int64(h.Sum64())
}

func insertSQL(table string, rows int) string {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(table)
	b.WriteString(" (chain, seq, version, ts, kind, payload, prev_hash, hash) VALUES ")
	for r := 0; r < rows; r++ {
		if r > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('(')
		for c := 0; c < 8; c++ {
			if c > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(r*8 + c + 1))
		}
		b.WriteByte(')')
	}
	return b.String()
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// Append implements hashchain.Store.
func (s *Store) Append(ctx context.Context, build func(head *hashchain.Entry) ([]hashchain.Entry, error)) (err error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("pgstore: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", s.lockKey); err != nil {
		return fmt.Errorf("pgstore: lock: %w", err)
	}
	var (
		head    *hashchain.Entry
		seq     int64
		hashCol []byte
	)
	switch err = tx.QueryRowContext(ctx, s.qHead, s.chain).Scan(&seq, &hashCol); {
	case errors.Is(err, sql.ErrNoRows):
		err = nil
	case err != nil:
		return fmt.Errorf("pgstore: read head: %w", err)
	default:
		head = &hashchain.Entry{Seq: uint64(seq), Hash: hashCol}
	}
	entries, err := build(head)
	if err != nil {
		return err
	}
	for start := 0; start < len(entries); start += insertChunk {
		chunk := entries[start:min(start+insertChunk, len(entries))]
		q := s.qInsert1
		if len(chunk) > 1 {
			q = insertSQL(s.table, len(chunk))
		}
		args := make([]any, 0, len(chunk)*8)
		for i := range chunk {
			e := &chunk[i]
			if e.Seq > math.MaxInt64 {
				return errors.New("pgstore: seq out of range")
			}
			args = append(args, s.chain, int64(e.Seq), int16(e.Version), e.Time,
				e.Kind, nonNil(e.Payload), nonNil(e.PrevHash), nonNil(e.Hash))
		}
		if _, err = tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("pgstore: insert: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("pgstore: commit: %w", err)
	}
	return nil
}

// Head implements hashchain.Store. The returned entry carries Seq and Hash.
func (s *Store) Head(ctx context.Context) (*hashchain.Entry, error) {
	var seq int64
	var h []byte
	err := s.db.QueryRowContext(ctx, s.qHead, s.chain).Scan(&seq, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: read head: %w", err)
	}
	return &hashchain.Entry{Seq: uint64(seq), Hash: h}, nil
}

// Scan implements hashchain.Store. It pages through the range with keyset
// pagination (WithPageSize rows per query), so memory use is bounded by one
// page and no long-running cursor or transaction is held.
func (s *Store) Scan(ctx context.Context, from, to uint64, fn func(*hashchain.Entry) error) error {
	if from > math.MaxInt64 {
		return nil
	}
	if to > math.MaxInt64 {
		to = math.MaxInt64
	}
	next := int64(from)
	for next <= int64(to) {
		n, last, err := s.scanPage(ctx, next, int64(to), fn)
		if err != nil {
			return err
		}
		if n < s.pageSize || last == math.MaxInt64 {
			return nil
		}
		next = last + 1
	}
	return nil
}

func (s *Store) scanPage(ctx context.Context, from, to int64, fn func(*hashchain.Entry) error) (n int, last int64, err error) {
	rows, err := s.db.QueryContext(ctx, s.qScan, s.chain, from, to, s.pageSize)
	if err != nil {
		return 0, 0, fmt.Errorf("pgstore: scan: %w", err)
	}
	defer rows.Close()
	var (
		e                      hashchain.Entry
		seq                    int64
		version                int16
		ts                     time.Time
		kind                   sql.RawBytes
		payload, prev, hashCol sql.RawBytes
	)
	for rows.Next() {
		if err := rows.Scan(&seq, &version, &ts, &kind, &payload, &prev, &hashCol); err != nil {
			return n, last, fmt.Errorf("pgstore: scan row: %w", err)
		}
		e = hashchain.Entry{
			Seq:      uint64(seq),
			Version:  uint8(version),
			Time:     ts.UTC(),
			Kind:     string(kind),
			Payload:  payload,
			PrevHash: prev,
			Hash:     hashCol,
		}
		if err := fn(&e); err != nil {
			return n, last, err
		}
		n++
		last = seq
	}
	if err := rows.Err(); err != nil {
		return n, last, fmt.Errorf("pgstore: scan: %w", err)
	}
	return n, last, nil
}
