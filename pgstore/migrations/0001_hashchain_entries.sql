-- hashchain: Postgres schema, version 1. Requires PostgreSQL 14 or later.
--
-- One table can hold many chains; the chain column names the chain.
-- pgstore.Migrate runs this file with the table name substituted when a
-- custom name is configured.

CREATE TABLE IF NOT EXISTS hashchain_entries (
    chain     text        NOT NULL,
    seq       bigint      NOT NULL CHECK (seq >= 0),
    version   smallint    NOT NULL CHECK (version BETWEEN 0 AND 255),
    ts        timestamptz NOT NULL,
    kind      text        NOT NULL,
    payload   bytea       NOT NULL,
    prev_hash bytea       NOT NULL,
    hash      bytea       NOT NULL,
    -- The primary key is the fork backstop: even a writer that bypasses
    -- the advisory lock cannot create two entries with the same seq.
    PRIMARY KEY (chain, seq)
);

-- Append-only guard. It stops accidental UPDATE, DELETE and TRUNCATE by
-- application code; it does not stop the table owner or a superuser, who
-- can disable triggers. Tamper evidence comes from the hashes, not from
-- this trigger.
CREATE OR REPLACE FUNCTION hashchain_entries_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'hashchain: table % is append-only', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE OR REPLACE TRIGGER hashchain_entries_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON hashchain_entries
    FOR EACH STATEMENT EXECUTE FUNCTION hashchain_entries_append_only();
