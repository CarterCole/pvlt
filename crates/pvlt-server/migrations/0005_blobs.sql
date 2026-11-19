-- pvlt key store, schema version 5: blobs.
--
-- A blob is a row in `facts` like any other, so shredding it (one blob, a scope, a subject, a domain), the shred
-- ledger, the audit log, legal hold and retention all apply with no special cases. What differs is how its
-- value is stored: as a streamed object the client encrypts itself, with `chunk_size` and the declared plaintext
-- length `blob_len` recorded so an upload can be checked without the key.
--
-- A blob starts `ready = false` (the client has been given a key and an upload address but the object may not
-- exist yet) and becomes ready when `complete` has checked what was uploaded. Until then it cannot be read, and
-- if it is never completed its short `expires_at` lets the retention sweeper shred it.

ALTER TABLE facts
    ADD COLUMN kind       text    NOT NULL DEFAULT 'fact' CHECK (kind IN ('fact', 'blob')),
    ADD COLUMN chunk_size integer CHECK (chunk_size IS NULL OR (chunk_size BETWEEN 1024 AND 16777216 AND chunk_size % 1024 = 0)),
    ADD COLUMN blob_len   bigint  CHECK (blob_len IS NULL OR blob_len >= 0),
    ADD COLUMN ready      boolean NOT NULL DEFAULT true,
    ADD COLUMN blob_expires_at timestamptz;

-- Facts keep their size classes; a blob has none.
ALTER TABLE facts DROP CONSTRAINT facts_size_class_check;
ALTER TABLE facts ADD CONSTRAINT facts_size_class_check CHECK (
    (kind = 'fact' AND size_class IN (256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304))
    OR (kind = 'blob' AND size_class = 0));

ALTER TABLE facts ADD CONSTRAINT facts_blob_columns CHECK (
    (kind = 'blob' AND chunk_size IS NOT NULL AND blob_len IS NOT NULL)
    OR (kind = 'fact' AND chunk_size IS NULL AND blob_len IS NULL AND ready));
