"""Tests for the Python client: request shapes against a local stub, and (when PVLT_TEST_* is set) the real server."""

import asyncio
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import pvlt_client as pv

SECRET = "Quentin-Q.-Nightingale-1987-03-09"


class Stub(BaseHTTPRequestHandler):
    seen: list = []
    responses: dict = {}

    def log_message(self, *args):  # silence
        pass

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        Stub.seen.append((self.command, self.path, dict(self.headers), body))
        status, payload = Stub.responses.get((self.command, self.path.split("?")[0]), (404, {"error": "not_found", "message": "not found"}))
        raw = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = do_DELETE = _go


class StubTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Stub)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Stub.seen.clear()
        Stub.responses.clear()

    def test_compat_store_get_delete_send_what_opv_clients_send(self):
        Stub.responses[("POST", "/api/v1/facts")] = (200, {"id": "abc"})
        Stub.responses[("GET", "/api/v1/facts/abc")] = (200, {"id": "abc", "value": SECRET})
        Stub.responses[("DELETE", "/api/v1/facts/abc")] = (204, None)
        c = pv.CompatClient(self.url, "tok")
        self.assertEqual(c.store("ascii", "kyc-doc:1", SECRET), "abc")
        self.assertEqual(c.get("abc"), SECRET)
        self.assertTrue(c.delete("abc"))
        method, path, headers, body = Stub.seen[0]
        self.assertEqual((method, path), ("POST", "/api/v1/facts"))
        self.assertEqual(headers["X-OPV-GRANT-TOKEN"], "tok")
        self.assertEqual(json.loads(body), {"fact_type_slug": "ascii", "scope_custom_id": "kyc-doc:1", "value": SECRET})

    def test_a_subject_is_sent_only_when_given(self):
        Stub.responses[("POST", "/api/v1/facts")] = (200, {"id": "x"})
        c = pv.CompatClient(self.url, "tok")
        c.store("ascii", "s", "v", subject="user:1")
        self.assertEqual(json.loads(Stub.seen[-1][3])["subject_custom_id"], "user:1")

    def test_errors_are_typed_and_carry_no_value_or_token(self):
        Stub.responses[("GET", "/api/v1/facts/gone")] = (410, {"error": "shredded", "message": "destroyed on purpose"})
        Stub.responses[("GET", "/api/v1/facts/sealed")] = (503, {"error": "sealed", "message": "vault is sealed"})
        c = pv.CompatClient(self.url, "very-secret-token")
        with self.assertRaises(pv.VaultError) as e:
            c.get("gone")
        self.assertEqual((e.exception.status, e.exception.code, e.exception.is_gone), (410, "shredded", True))
        with self.assertRaises(pv.VaultError) as e:
            c.get("sealed")
        self.assertEqual(e.exception.code, "sealed")
        self.assertNotIn("very-secret-token", str(e.exception))

    def test_delete_of_a_missing_fact_is_false_and_other_failures_raise(self):
        Stub.responses[("DELETE", "/api/v1/facts/none")] = (404, {"error": "not_found"})
        Stub.responses[("DELETE", "/api/v1/facts/held")] = (409, {"error": "conflict", "message": "legal hold"})
        c = pv.CompatClient(self.url, "tok")
        self.assertFalse(c.delete("none"))
        with self.assertRaises(pv.VaultError):
            c.delete("held")

    def test_the_async_functions_keep_the_old_contract(self):
        os.environ["OPV_URL"], os.environ["OPV_GRANT_TOKEN"] = self.url, "tok"
        Stub.responses[("POST", "/api/v1/facts")] = (200, {"id": "abc"})
        Stub.responses[("GET", "/api/v1/facts/abc")] = (200, {"value": SECRET})
        Stub.responses[("GET", "/api/v1/facts/bad")] = (503, {"error": "sealed"})
        Stub.responses[("DELETE", "/api/v1/facts/abc")] = (204, None)
        Stub.responses[("DELETE", "/api/v1/facts/gone")] = (404, {"error": "not_found"})
        Stub.responses[("DELETE", "/api/v1/facts/held")] = (409, {"error": "conflict"})
        run = asyncio.run
        self.assertEqual(run(pv.store_pii_fact("ascii", "s", SECRET)), {"id": "abc"})
        self.assertEqual(run(pv.get_pii_fact("abc")), SECRET)
        self.assertIsNone(run(pv.get_pii_fact("bad")), "any failure is None, as before")
        self.assertTrue(run(pv.delete_pii_fact("abc")))
        self.assertTrue(run(pv.delete_pii_fact("gone")), "an already-gone fact counts as success, as before")
        self.assertFalse(run(pv.delete_pii_fact("held")))
        del os.environ["OPV_GRANT_TOKEN"]
        self.assertIsNone(run(pv.store_pii_fact("ascii", "s", "v")))
        self.assertFalse(run(pv.delete_pii_fact("abc")))

    def test_the_failure_log_never_holds_the_value(self):
        os.environ["OPV_URL"], os.environ["OPV_GRANT_TOKEN"] = self.url, "tok"
        Stub.responses[("POST", "/api/v1/facts")] = (400, {"error": "invalid", "message": "value does not match fact_type_slug"})
        with self.assertLogs("pvlt", level="ERROR") as logs:
            self.assertIsNone(asyncio.run(pv.store_pii_fact("ascii", "s", SECRET)))
        self.assertNotIn("Nightingale", "\n".join(logs.output))

    def test_v2_sends_a_fresh_bearer_token_each_call_and_maps_refusals(self):
        Stub.responses[("POST", "/v2/facts")] = (200, {"id": "f1"})
        Stub.responses[("GET", "/v2/facts/f1")] = (403, {"error": "denied", "message": "purpose"})
        Stub.responses[("DELETE", "/v2/facts/f1")] = (200, {"outcome": "shredded", "count": 1})
        Stub.responses[("POST", "/v2/facts/batch")] = (200, {"ids": ["a", "b"]})
        Stub.responses[("POST", "/v2/shred/scope")] = (200, {"outcome": "shredded", "count": 3})
        tokens = iter(["t1", "t2", "t3", "t4", "t5"])
        c = pv.V2Client(self.url, lambda: next(tokens))
        self.assertEqual(c.create_fact("identity", "s", "v", subject="u", retain_days=30), "f1")
        with self.assertRaises(pv.VaultError) as e:
            c.read_fact("f1")
        self.assertEqual((e.exception.status, e.exception.code, e.exception.message), (403, "denied", "purpose"))
        self.assertEqual(c.shred("f1"), "shredded")
        self.assertEqual(c.create_facts([{"type": "a", "scope": "s", "value": "1"}, {"type": "b", "scope": "s", "value": "2"}]), ["a", "b"])
        self.assertEqual(c.shred_scope("s"), 3)
        self.assertEqual([h["Authorization"] for _, _, h, _ in Stub.seen], ["Bearer t1", "Bearer t2", "Bearer t3", "Bearer t4", "Bearer t5"])
        self.assertEqual(json.loads(Stub.seen[0][3]), {"type": "identity", "scope": "s", "value": "v", "subject": "u", "retain_days": 30})

    def test_a_connection_failure_is_a_vault_error_with_no_detail(self):
        c = pv.CompatClient("http://127.0.0.1:1", "tok", timeout=2)
        with self.assertRaises(pv.VaultError) as e:
            c.get("abc")
        self.assertEqual((e.exception.status, e.exception.code), (0, "unavailable"))
        self.assertNotIn("abc", str(e.exception))

    def test_bad_arguments_are_refused_up_front(self):
        for bad in ("not a url", "ftp://host", "https://"):
            with self.assertRaises(ValueError):
                pv.CompatClient(bad, "tok")
        with self.assertRaises(ValueError):
            pv.CompatClient("https://host:8443", "")


@unittest.skipUnless(os.environ.get("PVLT_TEST_URL"), "set PVLT_TEST_URL, PVLT_TEST_COMPAT_TOKEN and PVLT_CA_BUNDLE to test a real server")
class RealServerTests(unittest.TestCase):
    def test_the_three_opv_calls_and_a_shred_against_the_real_server(self):
        os.environ["OPV_URL"] = os.environ["PVLT_TEST_URL"]
        os.environ["OPV_GRANT_TOKEN"] = os.environ["PVLT_TEST_COMPAT_TOKEN"]
        stored = asyncio.run(pv.store_pii_fact("ascii", "kyc-doc:py", SECRET))
        self.assertIsNotNone(stored)
        self.assertEqual(asyncio.run(pv.get_pii_fact(stored["id"])), SECRET)
        self.assertTrue(asyncio.run(pv.delete_pii_fact(stored["id"])))
        self.assertIsNone(asyncio.run(pv.get_pii_fact(stored["id"])))
        c = pv.CompatClient(os.environ["PVLT_TEST_URL"], os.environ["PVLT_TEST_COMPAT_TOKEN"])
        with self.assertRaises(pv.VaultError) as e:
            c.get(stored["id"])
        self.assertTrue(e.exception.is_gone)


if __name__ == "__main__":
    unittest.main()
