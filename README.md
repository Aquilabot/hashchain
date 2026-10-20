# hashchain

An append-only, tamper-evident log for Go. Every entry commits to the hash of
the entry before it, so changing, removing, inserting or reordering a stored
entry breaks the chain at a point that verification reports exactly.

- Canonical, versioned binary encoding: exactly one byte layout per entry
- SHA-256 by default, any `crypto.Hash`, optional HMAC key for keyed chains
- Genesis entry that binds the chain to its hash configuration and name
- Full, range and checkpoint verification, streaming with O(1) memory
- Fork-free concurrent appends, including across processes on Postgres
- In-memory store and a Postgres store (`database/sql`, works with pgx and lib/pq)
- No dependencies outside the standard library (test-only: pgx, lib/pq)

```
go get github.com/Aquilabot/hashchain
```

Requires Go 1.25 or later. The Postgres store requires PostgreSQL 14 or later.

## Example

```go
import (
	"github.com/Aquilabot/hashchain"
	"github.com/Aquilabot/hashchain/pgstore"
	_ "github.com/jackc/pgx/v5/stdlib"
)

db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
if err := pgstore.Migrate(ctx, db); err != nil { ... }

store, _ := pgstore.New(db, "billing-audit")       // one table, many chains
chain, _ := hashchain.New(store, hashchain.Config{
	Key:  secretKey,                                // optional, enables HMAC
	Name: "billing-audit",                          // committed to by the genesis entry
})

entry, err := chain.Append(ctx, hashchain.Record{
	Kind:    "invoice.paid",
	Payload: []byte(`{"invoice":"inv_1","amount":4200}`),
})

report, err := chain.Verify(ctx)
var broken *hashchain.VerifyError
if errors.As(err, &broken) {
	// broken.Seq is the first broken position, broken.Reason one of
	// ErrHashMismatch, ErrBrokenLink, ErrSequence, ErrGenesis, ErrTruncated,
	// ErrCheckpointMismatch, ErrUnknownVersion, ErrEncoding.
	log.Printf("audit log tampered at seq %d: %v", broken.Seq, err)
}

// Publish the head somewhere the database operator cannot rewrite.
head, _ := chain.Head(ctx)                          // {Seq, Hash}
```

### API

| Call | What it does |
|---|---|
| `New(store, Config)` | Configure a chain over a `Store`. |
| `Append(ctx, Record)` | Append one entry, return it with `Seq`, `Time`, `PrevHash`, `Hash`. |
| `AppendBatch(ctx, ...Record)` | Append several entries in one store transaction. |
| `Head(ctx)` | Last `Checkpoint{Seq, Hash}`. Reads the stored hash; nothing is rehashed. |
| `Verify(ctx)` | Verify from the start of the chain to the current head. |
| `VerifyRange(ctx, from, to)` | Verify `from..to`, trusting the stored entry at `from-1` as the predecessor. |
| `VerifyFrom(ctx, checkpoint)` | Verify from a trusted checkpoint to the head; detects rewrites and truncation below it. |

A `Store` has three methods: `Append(ctx, build)`, `Head(ctx)`, `Scan(ctx,
from, to, fn)`. `Append` must call `build` with the current head while
holding exclusive write access to the chain and persist the result
atomically; that is the whole concurrency contract.

## Threat model

hashchain makes tampering *evident*. It does not prevent it.

**Detected** by `Verify`, with the first broken sequence number:

| Tampering | Reported as |
|---|---|
| An entry's kind, payload, time or stored hash is edited | `ErrHashMismatch` at that entry |
| An entry is edited and its hash recomputed (unkeyed chain) | `ErrBrokenLink` at the next entry |
| An entry is edited and rehashed on a keyed chain without the key | `ErrHashMismatch` at that entry |
| An entry is deleted from the middle | `ErrSequence` (or `ErrBrokenLink` if later entries are renumbered) |
| Two entries swap positions | `ErrBrokenLink` or `ErrSequence` |
| A forged entry is inserted | `ErrBrokenLink`, `ErrHashMismatch` or `ErrSequence` |
| The genesis entry is removed or replaced, or the chain is checked with the wrong hash function, key or name | `ErrGenesis` at seq 0 |

**Detected only with an external anchor** (a checkpoint stored outside the
attacker's reach, checked with `VerifyFrom`):

- Truncation: deleting the newest entries leaves a shorter chain that is still
  internally valid. `VerifyFrom` reports `ErrTruncated`.
- Whole-chain rewrite: an attacker who can write the store and knows the hash
  configuration (and the key, for keyed chains) can recompute every hash from
  the genesis entry on. Nothing inside the store can reveal that.
  `VerifyFrom` reports `ErrCheckpointMismatch`.

**Not detected:**

- An attacker who controls both the store and every anchor you check against.
- Entries that were never written. A compromised application can simply not
  log an event, or log a false one; the chain proves the log was not altered
  after the fact, not that it is true.
- Anything an attacker with the HMAC key can do on a keyed chain: the key adds
  protection only against attackers who can write the database but cannot
  read the application's secrets.

**Recommendation:** periodically publish the head checkpoint (`Head`) to a
place the database operator cannot rewrite, such as a different system's log,
a WORM bucket (S3 Object Lock), a signed message, a git commit, or a public
transparency log, and verify with `VerifyFrom` against the latest anchor.
How often you anchor bounds how much history can be silently truncated or
rewritten.

## Encoding (version 1)

Each entry's digest is `H(preimage)`, or `HMAC-H(key, preimage)` for keyed
chains, where `preimage` is:

| Field | Size | Encoding |
|---|---|---|
| domain tag | 10 | ASCII `hashchain` followed by `0x00` |
| version | 1 | `0x01` |
| seq | 8 | uint64, big-endian |
| time | 8 | int64, big-endian, Unix time in **microseconds**, UTC |
| kind length | 4 | uint32, big-endian |
| kind | n | UTF-8 bytes |
| payload length | 4 | uint32, big-endian |
| payload | m | raw bytes |
| prev hash length | 1 | uint8 |
| prev hash | k | raw digest bytes (empty for the first entry) |

`Entry.Hash` itself is never part of the preimage. A golden test vector pins
this layout (`TestV1GoldenVector`).

**Why length-prefixed binary.** The payload is
opaque bytes, so it needs no escaping, no Unicode normalization and no number
formatting rules; every entry has exactly one encoding, which `DecodeV1`
enforces by rejecting any input `AppendV1` would not produce. Binary framing is also fast: encoding a
typical entry takes about 13 ns with no allocations. Applications that want
JSON can put JSON in the payload.

**Time precision.** `Append` converts times to UTC and truncates them to whole
microseconds *before* hashing, because PostgreSQL `timestamptz` stores
microseconds. Hashing a finer precision than the store keeps makes entries
unverifiable after a round trip, a bug that is easy to ship and hard to
notice until the first audit.

**Kind** must be non-empty, valid UTF-8 and free of NUL bytes (Postgres `text`
rejects NUL).

**Genesis.** Unless `Config.NoGenesis` is set, the first append also writes
entry 0 with kind `hashchain.genesis`, an empty prev hash and this payload
(newline-separated, fixed order):

```
hashchain-genesis/1
hash=SHA-256
keyed=true
codec=1
name="billing-audit"
```

Verifying with a different hash function, key, codec or name fails at seq 0
with `ErrGenesis`, and entries cannot be spliced between chains with
different names. `NoGenesis` exists for chains that were started without a
genesis entry; their first entry is seq 1 with an empty prev hash.

**Versioning and legacy formats.** `Entry.Version` selects a `Codec`. New
entries use `Config.Codec` (default `V1Codec`); `Config.ExtraCodecs` lets a
chain verify entries written with older encodings, so moving to a new
encoding never requires rewriting history. A codec whose stored form cannot
reproduce the original preimage exactly (for example, a legacy format that
hashed nanosecond timestamps that the database then rounded) can implement
`HashMatcher` to decide matches itself.

## Postgres

```go
err := pgstore.Migrate(ctx, db)                          // or run the SQL yourself
ddl, _ := pgstore.MigrationSQL(pgstore.WithTable("audit_chain"))
store, _ := pgstore.New(db, "chain-name", pgstore.WithTable("audit_chain"))
```

The migration lives in
[`pgstore/migrations/0001_hashchain_entries.sql`](pgstore/migrations/0001_hashchain_entries.sql):
one table, primary key `(chain, seq)`, and a statement-level trigger that
rejects `UPDATE`, `DELETE` and `TRUNCATE`.

**Concurrent appends.** `Append` runs in a `READ COMMITTED` transaction:

1. `SELECT pg_advisory_xact_lock(key)`, where key is FNV-1a-64 of
   `"hashchain\0" + table + "\0" + chain` (`pgstore.LockKey`);
2. read the head (`ORDER BY seq DESC LIMIT 1` on the primary key);
3. compute and insert the new entries (multi-row `INSERT`, 500 rows per statement);
4. commit, which releases the lock.

Writers to the same chain are serialized across all connections and
processes; different chains do not block each other. The lock is
transaction-scoped, so it works behind PgBouncer in transaction pooling mode
(session-level advisory locks would not). The primary key is a backstop: two
entries can never share a sequence number, so even a writer that skips the
lock cannot fork the chain, it just fails. `READ COMMITTED` is required:
under `REPEATABLE READ` the snapshot would be taken before the lock was
granted and the head read could be stale.

**Verification reads** use keyset pagination (`WHERE seq >= $n ORDER BY seq
LIMIT 1000`, configurable with `WithPageSize`), so memory stays bounded by one
page and no long-lived cursor or transaction is held.

**Hardening.** Grant the application role only `SELECT` and `INSERT` on the
table. The trigger stops application bugs, not the table owner or a
superuser, who can disable it; the hashes and external anchors are what make
their changes visible.

## Performance

Measured on an AMD Ryzen 7 5800X3D, Go 1.27.2, linux/amd64, with
`go test -bench . -benchtime 2s -count 3` (range across the three runs).
Postgres is 17 (`postgres:17-alpine`) in Docker on the same machine, default
durability settings (`fsync=on`, `synchronous_commit=on`), so Postgres append
latency is dominated by the commit flush on this disk.

| Benchmark | Result |
|---|---|
| Encode one v1 preimage | 12–15 ns, 0 allocs |
| In-memory `Append` | 0.8–1.3 µs/op |
| In-memory `AppendBatch` of 100 | 0.50–0.58 µs/entry |
| In-memory `Verify`, 10k entries, SHA-256 | 179–217 ns/entry, 12 allocs total |
| In-memory `Verify`, 10k entries, HMAC-SHA-256 | 279–324 ns/entry |
| Postgres `Append` (one writer) | 6.4–7.4 ms/op |
| Postgres `Append` (64 goroutines, 32 connections, one chain) | 6.8–7.2 ms/op |
| Postgres `AppendBatch` of 100 | 78–83 µs/entry |
| Postgres `Verify`, 10k entries | 1.33–1.41 µs/entry |

Appends to one chain are serialized by design, so concurrent writers do not
increase throughput; batch when you can. Reads never rehash: `Head` returns
the stored hash and only `Verify*` recomputes digests.

## Testing

```
go test -race ./...                                 # starts postgres:17-alpine with Docker if available
HASHCHAIN_TEST_DSN=postgres://... go test ./...     # use an existing server instead
go test -run '^$' -fuzz FuzzV1RoundTrip -fuzztime 30s .
go test -run '^$' -fuzz FuzzV1Decode -fuzztime 30s .
```

Postgres tests are skipped when neither Docker nor `HASHCHAIN_TEST_DSN` is
available. The suite includes a tamper matrix (edit, rehash, delete,
reorder, insert, truncate, whole-chain rewrite) against the in-memory store
and the same attacks through SQL against Postgres, concurrent appends from
several connection pools, and fuzzing of the encoder and decoder.

## License

MIT. See [LICENSE](LICENSE).
