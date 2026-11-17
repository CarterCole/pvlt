# Contributing

Before sending a change, run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features pvlt-server/dev-insecure -- -D warnings
scripts/test-db.sh start && export PVLT_TEST_DATABASE_URL=$(scripts/test-db.sh url)
cargo test --workspace -- --include-ignored
(cd spec/reference && uv run gen_vectors.py --check)
```

`scripts/smoke.sh` runs the real binary against Postgres and MinIO containers. A change to a byte format must change
`docs/FORMAT.md`, the Python reference in `spec/` and the vectors together. Crypto, access-control and audit changes
need a test that fails without the change. Never log plaintext, keys or token values.
