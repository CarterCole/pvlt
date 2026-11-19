#!/usr/bin/env python3
"""Checks a finished `pvlt import-opv` independently of the importer (docs/MIGRATING.md, check V4).

    verify_opv_import.py --csv FILE --opv-url URL --opv-token-file F --vault-url URL --vault-token-file F
                         [--cacert PEM]... [--sample K]

For every CSV row (or K random rows), reads the fact from OPV and from pvlt's /api/v1, both with
X-OPV-GRANT-TOKEN, and checks that pvlt has it, under the same id, with the CSV's type and the same value
(compared as SHA-256 of the UTF-8 bytes). Prints ids, statuses and counts, never a value. Exit 0 if every row
checked is fine, 1 if any is not, 2 for a usage error.

Standard library only. Values pass through this process's memory one row at a time and are not written anywhere.
Each read through pvlt is an audited `read.grant` by `compat`.
"""
import argparse
import csv
import hashlib
import json
import random
import ssl
import sys
import urllib.error
import urllib.request


def secret(path):
    with open(path, encoding="utf-8") as f:
        value = f.read().rstrip("\r\n")
    if not value:
        sys.exit(f"{path} is empty")
    return value


def fetch(ctx, base, token, fact_id):
    """(status, body or None). The body is parsed JSON for a 200."""
    req = urllib.request.Request(
        f"{base}/api/v1/facts/{fact_id}", headers={"X-OPV-GRANT-TOKEN": token}
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return "unreachable", None


def digest(body):
    value = body.get("value") if isinstance(body, dict) else None
    return hashlib.sha256(value.encode()).digest() if isinstance(value, str) else None


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--csv", required=True)
    p.add_argument("--opv-url", required=True)
    p.add_argument("--opv-token-file", required=True)
    p.add_argument("--vault-url", required=True)
    p.add_argument("--vault-token-file", required=True)
    p.add_argument("--cacert", action="append", default=[])
    p.add_argument("--sample", type=int)
    a = p.parse_args()

    ctx = ssl.create_default_context()
    for pem in a.cacert:
        ctx.load_verify_locations(cafile=pem)
    opv_token, vault_token = secret(a.opv_token_file), secret(a.vault_token_file)
    opv, vault = a.opv_url.rstrip("/"), a.vault_url.rstrip("/")

    with open(a.csv, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        if next(reader, None) != ["id", "subject", "scope", "type"]:
            sys.exit("the CSV header must be exactly: id,subject,scope,type")
        rows = [(r[0].strip(), r[3]) for r in reader if r]
    if a.sample is not None and a.sample < len(rows):
        rows = random.sample(rows, a.sample)

    problems = 0
    for fact_id, fact_type in rows:
        status, source = fetch(ctx, opv, opv_token, fact_id)
        if status != 200 or digest(source) is None:
            problems += 1
            print(f"opv {fact_id}: {status if status != 200 else 'no value'}")
            continue
        status, target = fetch(ctx, vault, vault_token, fact_id)
        if status != 200 or digest(target) is None:
            problems += 1
            print(f"vault {fact_id}: {status if status != 200 else 'no value'}")
        elif str(target.get("id", "")).lower() != fact_id.lower():
            problems += 1
            print(f"ID {fact_id}: the vault answered for a different id")
        elif target.get("fact_type_slug") != fact_type:
            problems += 1
            print(f"TYPE {fact_id}: the vault has {target.get('fact_type_slug')}, the CSV says {fact_type}")
        elif digest(target) != digest(source):
            problems += 1
            print(f"MISMATCH {fact_id}")
        source = target = None
    print(f"checked {len(rows)}  ok {len(rows) - problems}  problems {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
