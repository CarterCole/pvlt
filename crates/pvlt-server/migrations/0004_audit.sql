-- pvlt key store, schema version 4: the audit log, and signing keys by purpose.

-- A domain now has two signing keys: one for ledger entries and one for checkpoints.
ALTER TABLE sign_keys DROP CONSTRAINT sign_keys_pkey;
ALTER TABLE sign_keys ADD COLUMN purpose text NOT NULL DEFAULT 'ledger' CHECK (purpose IN ('ledger', 'checkpoint'));
ALTER TABLE sign_keys ADD PRIMARY KEY (domain_id, purpose);

-- The audit log (FORMAT.md section 8). Entries are hash-chained. `line` is the canonical JSON entry and is the
-- record; the other columns are copies for the indexes that answer "who read subject X" and are checked
-- against `line` whenever the log is verified. The table is append-only: no row can be changed or deleted.
CREATE TABLE audit (
    domain_id    bytea  NOT NULL REFERENCES domains (domain_id),
    seq          bigint NOT NULL CHECK (seq >= 0),
    prev_hash    bytea  NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash   bytea  NOT NULL CHECK (octet_length(entry_hash) = 32),
    line         bytea  NOT NULL CHECK (octet_length(line) > 0),
    at           timestamptz NOT NULL DEFAULT now(),
    kind         text   NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 32),
    principal    text   NOT NULL CHECK (char_length(principal) BETWEEN 1 AND 256),
    fact_id      uuid,
    subject_hmac bytea  CHECK (subject_hmac IS NULL OR octet_length(subject_hmac) = 32),
    PRIMARY KEY (domain_id, seq),
    CONSTRAINT audit_entry_hash_key UNIQUE (domain_id, entry_hash)
);

CREATE INDEX audit_by_subject   ON audit (domain_id, subject_hmac, seq) WHERE subject_hmac IS NOT NULL;
CREATE INDEX audit_by_principal ON audit (domain_id, principal, seq);
CREATE INDEX audit_by_fact      ON audit (domain_id, fact_id, seq) WHERE fact_id IS NOT NULL;
CREATE INDEX audit_by_time      ON audit (domain_id, at);

CREATE FUNCTION pvlt_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit rows cannot be changed or deleted' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION pvlt_audit_append_only();
