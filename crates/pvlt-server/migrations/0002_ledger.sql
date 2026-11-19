-- pvlt key store, schema version 2: the shred ledger and signing keys.
--
-- A ledger row is written in the same transaction that destroys the keys it describes, so a shred and its
-- record cannot come apart. The database refuses to delete a ledger row or to change anything in one except
-- flipping `published` from false to true (the entry reached the bucket).

-- One Ed25519 ledger signing key per domain. The seed is wrapped by the root key; the public key is not secret
-- and lets a ledger be verified while the vault is sealed.
CREATE TABLE sign_keys (
    domain_id        bytea  PRIMARY KEY REFERENCES domains (domain_id) CHECK (octet_length(domain_id) = 16),
    key_id           bytea  NOT NULL CHECK (octet_length(key_id) = 16),
    root_key_version bigint NOT NULL CHECK (root_key_version BETWEEN 1 AND 4294967295),
    wrapped_seed     bytea  NOT NULL CHECK (octet_length(wrapped_seed) = 107),
    public_key       bytea  NOT NULL CHECK (octet_length(public_key) = 32),
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ledger (
    domain_id  bytea  NOT NULL REFERENCES domains (domain_id),
    seq        bigint NOT NULL CHECK (seq >= 0),
    prev_hash  bytea  NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash bytea  NOT NULL CHECK (octet_length(entry_hash) = 32),
    line       bytea  NOT NULL CHECK (octet_length(line) > 0),
    published  boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, seq),
    CONSTRAINT ledger_entry_hash_key UNIQUE (domain_id, entry_hash)
);

CREATE FUNCTION pvlt_ledger_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger rows cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.domain_id IS DISTINCT FROM OLD.domain_id OR NEW.seq IS DISTINCT FROM OLD.seq
       OR NEW.prev_hash IS DISTINCT FROM OLD.prev_hash OR NEW.entry_hash IS DISTINCT FROM OLD.entry_hash
       OR NEW.line IS DISTINCT FROM OLD.line OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.published AND NOT NEW.published) THEN
        RAISE EXCEPTION 'a ledger row cannot be changed' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER ledger_append_only BEFORE UPDATE OR DELETE ON ledger
    FOR EACH ROW EXECUTE FUNCTION pvlt_ledger_append_only();

CREATE FUNCTION pvlt_sign_keys_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a signing key cannot be changed or deleted' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER sign_keys_immutable BEFORE UPDATE OR DELETE ON sign_keys
    FOR EACH ROW EXECUTE FUNCTION pvlt_sign_keys_immutable();
