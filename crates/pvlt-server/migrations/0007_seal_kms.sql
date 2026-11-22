-- pvlt key store, schema version 7: auto-unseal.
--
-- The unseal key (the one the Shamir shares recover) can also be wrapped by a KMS, so a restart opens the vault
-- without people. This table holds that wrapped copy: ciphertext only, useless without the KMS's decrypt
-- permission on the named key. The shares keep working; they remain the way back in if the KMS is gone.
--
-- It is deliberately not part of a backup: it ties the vault to one KMS key in one environment, so a restore
-- into another place enrols again with `pvlt kms-enroll`.

CREATE TABLE seal_kms (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    root_key_id  bytea   NOT NULL CHECK (octet_length(root_key_id) = 16),
    provider     text    NOT NULL CHECK (provider IN ('aws-kms')),
    key_id       text    NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 2048),
    wrapped      bytea   NOT NULL CHECK (octet_length(wrapped) BETWEEN 1 AND 8192),
    created_at   timestamptz NOT NULL DEFAULT now()
);
