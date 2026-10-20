# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- `Chain` with `Append`, `AppendBatch`, `Head`, `Verify`, `VerifyRange` and
  `VerifyFrom`.
- Canonical length-prefixed binary encoding, version 1 (`AppendV1`,
  `DecodeV1`), with microsecond UTC timestamps and a domain separation tag.
- Configurable hash function (`crypto.Hash`, SHA-256 by default) and optional
  HMAC key.
- Genesis entry binding a chain to its hash function, keying, codec and name;
  `NoGenesis` for chains created without one.
- `Codec`, `ExtraCodecs` and `HashMatcher` for verifying entries written with
  older or legacy encodings.
- `VerifyError` with the first broken sequence number and a reason sentinel.
- `MemoryStore`.
- `pgstore`: Postgres store over `database/sql` with transaction-scoped
  advisory locking, keyset-paginated scans, an idempotent migration and an
  append-only trigger.
