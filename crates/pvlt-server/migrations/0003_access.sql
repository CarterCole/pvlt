-- pvlt key store, schema version 3: token issuers, policy versions and dual-control approvals.

-- A registered issuer of request tokens. `key_id` is the root key id written into its tokens.
CREATE TABLE issuers (
    key_id     integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       text    NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 64),
    public_key bytea   NOT NULL CHECK (octet_length(public_key) = 32),
    roles      text[]  NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every policy ever set, newest wins. Rows never change, so the history of what was allowed is complete.
CREATE TABLE policies (
    version    bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    doc        bytea   NOT NULL CHECK (octet_length(doc) > 0),
    hash       bytea   NOT NULL CHECK (octet_length(hash) = 32),
    created_by text    NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION pvlt_policies_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a policy version cannot be changed or deleted' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER policies_immutable BEFORE UPDATE OR DELETE ON policies
    FOR EACH ROW EXECUTE FUNCTION pvlt_policies_immutable();

-- A request, by one admin, to read one fact once, which a different admin approves. The database enforces that
-- the approver is not the requester unless the request is marked break-glass, and that an approval is used once.
CREATE TABLE approvals (
    id           uuid   PRIMARY KEY,
    domain_id    bytea  NOT NULL REFERENCES domains (domain_id),
    fact_id      uuid   NOT NULL,
    requested_by text   NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 64),
    approved_by  text   CHECK (approved_by IS NULL OR char_length(approved_by) BETWEEN 1 AND 64),
    break_glass  boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    approved_at  timestamptz,
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    CONSTRAINT approvals_two_people CHECK (approved_by IS NULL OR break_glass OR approved_by <> requested_by),
    CONSTRAINT approvals_approved_at CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT approvals_used_after_approval CHECK (used_at IS NULL OR approved_by IS NOT NULL),
    CONSTRAINT approvals_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX approvals_by_fact ON approvals (domain_id, fact_id);
