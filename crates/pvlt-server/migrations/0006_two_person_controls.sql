-- pvlt key store, schema version 6: controls that need two people, or that bind a capability to one.
--
-- * An approval names the one caller (a token's `caller` claim) who may spend it. Rows made before this have no
--   reader, and no token can use them; approvals live for minutes, so none is lost that matters.
-- * A change to who may do what (a policy, a new issuer, re-enabling one) waits in `admin_changes` until a
--   second admin approves it. The database enforces the two people and single approval.
-- * The seal configuration records a hash of every share dealt at `init`, so a forged share is refused on its own.

ALTER TABLE approvals
    ADD COLUMN reader text CHECK (reader IS NULL OR char_length(reader) BETWEEN 1 AND 256);

CREATE TABLE admin_changes (
    id           uuid   PRIMARY KEY,
    kind         text   NOT NULL CHECK (kind IN ('policy.set', 'issuer.create', 'issuer.enable')),
    payload      bytea  NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    requested_by text   NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 64),
    approved_by  text   CHECK (approved_by IS NULL OR char_length(approved_by) BETWEEN 1 AND 64),
    created_at   timestamptz NOT NULL DEFAULT now(),
    approved_at  timestamptz,
    expires_at   timestamptz NOT NULL,
    CONSTRAINT admin_changes_two_people CHECK (approved_by IS NULL OR approved_by <> requested_by),
    CONSTRAINT admin_changes_approved_at CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT admin_changes_expiry_after_creation CHECK (expires_at > created_at)
);

-- Once approved, a change is history: it cannot be edited, re-approved or removed.
CREATE FUNCTION pvlt_admin_changes_settled() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.approved_by IS NOT NULL
       OR NEW.id <> OLD.id OR NEW.kind <> OLD.kind OR NEW.payload <> OLD.payload
       OR NEW.requested_by <> OLD.requested_by OR NEW.expires_at <> OLD.expires_at
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'an admin change can only be approved, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER admin_changes_settled BEFORE UPDATE OR DELETE ON admin_changes
    FOR EACH ROW EXECUTE FUNCTION pvlt_admin_changes_settled();

-- `share number (1 byte) ‖ SHA-256 commitment (32 bytes)` for each share dealt, in one column.
ALTER TABLE seal_config
    ADD COLUMN shamir_share_checks bytea CHECK (
        shamir_share_checks IS NULL
        OR (mode = 'shamir' AND octet_length(shamir_share_checks) > 0 AND octet_length(shamir_share_checks) % 33 = 0)
    );
