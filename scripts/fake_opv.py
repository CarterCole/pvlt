#!/usr/bin/env python3
"""A stand-in for Open Privacy Vault's data plane, for rehearsing a migration (scripts/smoke.sh).

    fake_opv.py PORT TOKEN FACTS.json [FAIL_ID]

Serves GET /api/v1/facts/{id} with the X-OPV-GRANT-TOKEN header, from a JSON object of id -> value. If
FAIL_ID is given, the first TWO requests for that id answer 500 and later ones succeed (a dry run uses one, the
first real run the other), which is what a flaky upstream looks like to a resumable importer. Plaintext HTTP on 127.0.0.1 only. Test data only.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port, token, path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
fail_id = sys.argv[4] if len(sys.argv) > 4 else None
facts = json.load(open(path))
failures = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("X-OPV-GRANT-TOKEN") != token:
            return self._send(401, {"error": "unauthorized"})
        fact_id = self.path.rsplit("/", 1)[-1]
        if fail_id and fact_id == fail_id and failures.get(fact_id, 0) < 2:
            failures[fact_id] = failures.get(fact_id, 0) + 1
            return self._send(500, {"error": "flaky"})
        if fact_id not in facts:
            return self._send(404, {"error": "not found"})
        self._send(200, {"id": fact_id, "value": facts[fact_id]})

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
