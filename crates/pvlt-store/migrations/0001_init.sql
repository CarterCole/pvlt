-- pvlt key store, schema version 1.
--
-- Nothing in this schema can hold a plaintext fact value, a plaintext subject or scope, or an unwrapped key.
-- Every key column is a wrapped key (107 bytes, FORMAT.md section 5) and every subject and scope is a 32-byte
-- HMAC (section 6). The sealed values themselves are in the object store.
--
-- The database enforces what it can, so a bug in the vault cannot put a malformed or resurrected row in:
--   * every id, hash and wrapped key has its exact length;
--   * a shredded row must hold zeros where its keys were, and must have a shredded_at;
--   * a shredded row can never be changed again (trigger below), so nothing can write a key back into it.
--
-- Baseline PostgreSQL 17. Tested on 15, 16, 17 and 18.

CREATE TABLE seal_config (
    singleton        boolean  PRIMARY KEY DEFAULT true CHECK (singleton),
    root_key_id      bytea    NOT NULL CHECK (octet_length(root_key_id) = 16),
    root_key_version bigint   NOT NULL CHECK (root_key_version BETWEEN 1 AND 4294967295),
    wrapped_root     bytea    NOT NULL CHECK (octet_length(wrapped_root) = 107),
    mode             text     NOT NULL CHECK (mode IN ('shamir', 'passphrase')),
    shamir_threshold smallint,
    shamir_shares    smallint,
    pass_m_kib       bigint,
    pass_t_cost      bigint,
    pass_p_cost      bigint,
    pass_salt        bytea,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT seal_config_mode_columns CHECK (
        (mode = 'shamir'
            AND shamir_threshold IS NOT NULL AND shamir_shares IS NOT NULL
            AND shamir_threshold BETWEEN 2 AND 255
            AND shamir_shares BETWEEN shamir_threshold AND 255
            AND pass_m_kib IS NULL AND pass_t_cost IS NULL AND pass_p_cost IS NULL AND pass_salt IS NULL)
        OR
        (mode = 'passphrase'
            AND shamir_threshold IS NULL AND shamir_shares IS NULL
            AND pass_m_kib IS NOT NULL AND pass_t_cost IS NOT NULL AND pass_p_cost IS NOT NULL
            AND pass_salt IS NOT NULL AND octet_length(pass_salt) = 16)
    )
);

CREATE TABLE domains (
    domain_id    bytea  PRIMARY KEY CHECK (octet_length(domain_id) = 16),
    state        text   NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'shredded')),
    kek_version  bigint NOT NULL CHECK (kek_version BETWEEN 1 AND 4294967295),
    wrapped_kek  bytea  NOT NULL CHECK (octet_length(wrapped_kek) = 107),
    bik_version  bigint NOT NULL CHECK (bik_version BETWEEN 1 AND 4294967295),
    wrapped_bik  bytea  NOT NULL CHECK (octet_length(wrapped_bik) = 107),
    bix_version  bigint NOT NULL CHECK (bix_version BETWEEN 1 AND 4294967295),
    wrapped_bix  bytea  NOT NULL CHECK (octet_length(wrapped_bix) = 107),
    created_at   timestamptz NOT NULL DEFAULT now(),
    shredded_at  timestamptz,
    CONSTRAINT domains_shredded_at CHECK ((state = 'shredded') = (shredded_at IS NOT NULL)),
    CONSTRAINT domains_shredded_keys_are_zero CHECK (
        state = 'active' OR (
            wrapped_kek = decode(repeat('00', 107), 'hex')
            AND wrapped_bik = decode(repeat('00', 107), 'hex')
            AND wrapped_bix = decode(repeat('00', 107), 'hex'))
    )
);

CREATE TABLE subject_keys (
    domain_id    bytea  NOT NULL REFERENCES domains (domain_id),
    subject_hmac bytea  NOT NULL CHECK (octet_length(subject_hmac) = 32),
    version      bigint NOT NULL CHECK (version BETWEEN 1 AND 4294967295),
    bik_version  bigint NOT NULL CHECK (bik_version BETWEEN 1 AND 4294967295),
    kek_version  bigint NOT NULL CHECK (kek_version BETWEEN 1 AND 4294967295),
    wrapped_key  bytea  NOT NULL CHECK (octet_length(wrapped_key) = 107),
    state        text   NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'shredded')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    shredded_at  timestamptz,
    PRIMARY KEY (domain_id, subject_hmac, version),
    CONSTRAINT subject_keys_shredded_at CHECK ((state = 'shredded') = (shredded_at IS NOT NULL)),
    CONSTRAINT subject_keys_shredded_key_is_zero CHECK (
        state = 'active' OR wrapped_key = decode(repeat('00', 107), 'hex'))
);

CREATE TABLE facts (
    domain_id           bytea  NOT NULL,
    fact_id             uuid   NOT NULL,
    subject_hmac        bytea  NOT NULL CHECK (octet_length(subject_hmac) = 32),
    subject_key_version bigint NOT NULL CHECK (subject_key_version BETWEEN 1 AND 4294967295),
    bik_version         bigint NOT NULL CHECK (bik_version BETWEEN 1 AND 4294967295),
    scope_hmac          bytea  NOT NULL CHECK (octet_length(scope_hmac) = 32),
    fact_type           text   NOT NULL CHECK (octet_length(fact_type) BETWEEN 1 AND 64),
    object_id           bytea  NOT NULL CHECK (octet_length(object_id) = 16),
    size_class          integer NOT NULL
                        CHECK (size_class IN (256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304)),
    dek_generation      bigint NOT NULL CHECK (dek_generation BETWEEN 0 AND 4294967295),
    wrapped_dek         bytea  NOT NULL CHECK (octet_length(wrapped_dek) = 107),
    state               text   NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'shredded')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz,
    legal_hold          boolean NOT NULL DEFAULT false,
    shredded_at         timestamptz,
    CONSTRAINT facts_pkey PRIMARY KEY (domain_id, fact_id),
    CONSTRAINT facts_object_id_key UNIQUE (domain_id, object_id),
    CONSTRAINT facts_subject_key_fkey FOREIGN KEY (domain_id, subject_hmac, subject_key_version)
        REFERENCES subject_keys (domain_id, subject_hmac, version),
    CONSTRAINT facts_shredded_at CHECK ((state = 'shredded') = (shredded_at IS NOT NULL)),
    CONSTRAINT facts_shredded_key_is_zero CHECK (
        state = 'active' OR wrapped_dek = decode(repeat('00', 107), 'hex'))
);

-- Subject shred and scope shred find facts by these.
CREATE INDEX facts_by_subject ON facts (domain_id, subject_hmac);
CREATE INDEX facts_by_scope   ON facts (domain_id, scope_hmac);
-- The retention sweeper finds due facts by this.
CREATE INDEX facts_due ON facts (expires_at) WHERE state = 'active' AND expires_at IS NOT NULL;

-- A shredded row never changes again. Without this, one wrong UPDATE could write a key back and undo an erasure.
CREATE FUNCTION pvlt_forbid_changing_shredded() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = 'shredded' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'a shredded row cannot be changed' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER domains_no_change_after_shred      BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION pvlt_forbid_changing_shredded();
CREATE TRIGGER subject_keys_no_change_after_shred BEFORE UPDATE ON subject_keys
    FOR EACH ROW EXECUTE FUNCTION pvlt_forbid_changing_shredded();
CREATE TRIGGER facts_no_change_after_shred        BEFORE UPDATE ON facts
    FOR EACH ROW EXECUTE FUNCTION pvlt_forbid_changing_shredded();
