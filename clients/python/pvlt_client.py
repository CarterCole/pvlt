"""A client for pvlt. Pre-alpha: do not use with real personal data.

Standard library only. Two ways in, matching the two APIs the server has:

* ``store_pii_fact`` / ``get_pii_fact`` / ``delete_pii_fact``: the same three async functions, with the same
  arguments and return values, as an OPV client's ``privacy.py``. Replace that module's body (or import these
  names from here) and set ``OPV_URL`` to the vault and ``OPV_GRANT_TOKEN`` to the compat token. They keep the
  old behaviour on purpose: any failure is ``None`` or ``False``, and the error is logged without the value.
* ``V2Client``: the native API, with a short-lived request token per call, typed errors and the shred routes.
  Request tokens are minted by *your* service (for example with ``biscuit-python``, or ``pvlt mint-token`` in
  tests); this client only presents them.

Trust a private CA with ``PVLT_CA_BUNDLE=/path/to/ca.pem`` (or ``ca_bundle=``). Certificates are always
verified: there is no option to turn that off.

Blobs: this client reads them (``V2Client.read_blob_content``, which has the server decrypt and stream) but does
not encrypt them. Client-side encryption for uploads is in ``clients/typescript``.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import ssl
import urllib.parse
from typing import Any, Callable, Optional, Union

log = logging.getLogger("pvlt")

DEFAULT_TIMEOUT = 20.0


class VaultError(Exception):
    """The vault refused or could not do something.

    ``status`` is the HTTP status (0 if there was no response), ``code`` the stable error code from the server
    (``denied``, ``shredded``, ``not_found``, ``sealed``, ``rate_limited``, ``unavailable``, ``invalid``,
    ``conflict``), and ``message`` fixed text from the server. Nothing here holds a value or a token.
    """

    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(f"{status} {code}: {message}" if message else f"{status} {code}")
        self.status = status
        self.code = code
        self.message = message

    @property
    def is_gone(self) -> bool:
        """True if the fact was destroyed on purpose. Permanent: do not retry."""
        return self.code == "shredded"


def _context(ca_bundle: Optional[str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle or os.environ.get("PVLT_CA_BUNDLE") or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


class _Http:
    def __init__(self, base_url: str, ca_bundle: Optional[str], timeout: float) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("base_url must look like https://host:port")
        self._https = parts.scheme == "https"
        self._host = parts.hostname
        self._port = parts.port or (443 if self._https else 80)
        self._prefix = parts.path.rstrip("/")
        self._timeout = timeout
        self._ctx = _context(ca_bundle) if self._https else None

    def request(
        self, method: str, path: str, headers: dict, body: Optional[bytes] = None
    ) -> tuple[int, dict, bytes]:
        if self._https:
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                self._host, self._port, timeout=self._timeout, context=self._ctx
            )
        else:
            conn = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            conn.request(method, self._prefix + path, body=body, headers=headers)
            res = conn.getresponse()
            data = res.read()
            return res.status, {k.lower(): v for k, v in res.getheaders()}, data
        except (OSError, http.client.HTTPException) as e:
            # Never include the exception text: a library message can quote a URL, and URLs can hold ids.
            raise VaultError(0, "unavailable", f"could not reach the vault ({type(e).__name__})") from None
        finally:
            conn.close()


def _error(status: int, data: bytes) -> VaultError:
    try:
        j = json.loads(data)
        return VaultError(status, str(j.get("error", "error")), str(j.get("message", "")))
    except (ValueError, AttributeError):
        return VaultError(status, "error", "")


class CompatClient:
    """The OPV-compatible routes: ``POST /api/v1/facts``, ``GET``, ``DELETE`` with ``X-OPV-GRANT-TOKEN``."""

    def __init__(
        self, url: str, token: str, ca_bundle: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        if not token:
            raise ValueError("a token is required")
        self._http = _Http(url, ca_bundle, timeout)
        self._token = token

    def _headers(self, json_body: bool = False) -> dict:
        h = {"X-OPV-GRANT-TOKEN": self._token}
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    def store(self, fact_type: str, scope: str, value: str, subject: Optional[str] = None) -> str:
        """Stores a fact and returns its id. ``subject`` is optional; without it a subject shred cannot reach it."""
        body = {"fact_type_slug": fact_type, "scope_custom_id": scope, "value": value}
        if subject:
            body["subject_custom_id"] = subject
        status, _, data = self._http.request(
            "POST", "/api/v1/facts", self._headers(True), json.dumps(body).encode()
        )
        if status != 200:
            raise _error(status, data)
        return str(json.loads(data)["id"])

    def get(self, fact_id: str) -> str:
        """Returns a fact's value. Raises ``VaultError`` (``not_found``, ``shredded``, ...)."""
        status, _, data = self._http.request("GET", f"/api/v1/facts/{fact_id}", self._headers())
        if status != 200:
            raise _error(status, data)
        return str(json.loads(data)["value"])

    def delete(self, fact_id: str) -> bool:
        """Shreds a fact. True if it was destroyed or already gone, False if it never existed."""
        status, _, data = self._http.request("DELETE", f"/api/v1/facts/{fact_id}", self._headers())
        if status in (200, 204):
            return True
        if status == 404:
            return False
        raise _error(status, data)


# --- The three functions an OPV client already calls ---------------------------------------------------------


def _compat() -> Optional[CompatClient]:
    token = os.environ.get("OPV_GRANT_TOKEN")
    if not token:
        log.warning("OPV_GRANT_TOKEN not set. Cannot reach the vault.")
        return None
    return CompatClient(os.environ.get("OPV_URL", "https://pvlt:8443"), token)


async def store_pii_fact(fact_type: str, scope_id: str, value: str) -> Optional[dict]:
    """Stores a fact. Returns ``{"id": ...}``, or ``None`` on any failure (the caller aborts without committing)."""
    client = _compat()
    if client is None:
        return None
    try:
        return {"id": await asyncio.to_thread(client.store, fact_type, scope_id, value)}
    except (VaultError, ValueError) as e:
        log.error("Failed to store PII in the vault: %s", e)
        return None


async def get_pii_fact(fact_id: str) -> Optional[str]:
    """Returns a fact's value, or ``None`` on any failure."""
    client = _compat()
    if client is None:
        return None
    try:
        return await asyncio.to_thread(client.get, fact_id)
    except (VaultError, ValueError) as e:
        log.error("Failed to retrieve PII from the vault: %s", e)
        return None


async def delete_pii_fact(fact_id: str) -> bool:
    """Shreds a fact. ``True`` on success, and also if it was already gone (as OPV clients expect)."""
    client = _compat()
    if client is None:
        return False
    try:
        await asyncio.to_thread(client.delete, fact_id)
        return True
    except (VaultError, ValueError) as e:
        log.error("Failed to delete PII from the vault: %s", e)
        return False


# --- The native API -------------------------------------------------------------------------------------------

TokenSource = Union[str, Callable[[], str]]


class V2Client:
    """The native ``/v2`` API with delegated request tokens.

    ``token`` is a request token or a function that returns a fresh one; it is called for every request,
    because tokens live for a minute or so. Every refusal is a ``VaultError`` with the server's stable code.
    """

    def __init__(
        self,
        base_url: str,
        token: TokenSource,
        ca_bundle: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._http = _Http(base_url, ca_bundle, timeout)
        self._token = token

    def _headers(self, json_body: bool = False) -> dict:
        token = self._token() if callable(self._token) else self._token
        h = {"Authorization": f"Bearer {token}"}
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    def _json(self, method: str, path: str, body: Optional[Any] = None) -> Any:
        raw = None if body is None else json.dumps(body).encode()
        status, _, data = self._http.request(method, path, self._headers(body is not None), raw)
        if status < 200 or status >= 300:
            raise _error(status, data)
        return json.loads(data) if data else None

    def create_fact(
        self,
        fact_type: str,
        scope: str,
        value: str,
        subject: Optional[str] = None,
        retain_days: Optional[int] = None,
    ) -> str:
        """Stores a fact and returns its id."""
        body: dict = {"type": fact_type, "scope": scope, "value": value}
        if subject is not None:
            body["subject"] = subject
        if retain_days is not None:
            body["retain_days"] = retain_days
        return str(self._json("POST", "/v2/facts", body)["id"])

    def create_facts(self, facts: list[dict]) -> list[str]:
        """Stores several facts atomically: all of them or none. Each dict has ``type``, ``scope``, ``value`` and
        optionally ``subject`` and ``retain_days``. Returns the ids in order."""
        return [str(i) for i in self._json("POST", "/v2/facts/batch", {"facts": facts})["ids"]]

    def read_fact(self, fact_id: str) -> dict:
        """Returns ``{"id", "type", "value"}`` (or ``value_b64`` for bytes that are not text)."""
        return self._json("GET", f"/v2/facts/{fact_id}")

    def shred(self, fact_id: str) -> str:
        """Shreds one fact or blob. Returns ``shredded``, ``already_shredded`` or ``not_found``."""
        return str(self._json("DELETE", f"/v2/facts/{fact_id}")["outcome"])

    def shred_subject(self, subject: str, reason: str = "subject_request") -> str:
        """Destroys every fact filed under a subject. Needs a token whose role may shred every type."""
        return str(self._json("POST", "/v2/shred/subject", {"subject": subject, "reason": reason})["outcome"])

    def shred_scope(self, scope: str, reason: str = "admin") -> int:
        """Destroys every fact in a scope. Returns how many."""
        return int(self._json("POST", "/v2/shred/scope", {"scope": scope, "reason": reason})["count"])

    def read_blob_content(self, blob_id: str) -> bytes:
        """Has the vault decrypt a blob and stream the plaintext. The disclosure is written to the audit log first.

        If the transfer ends early the vault is saying the blob failed verification: this raises and returns
        nothing, because ``http.client`` raises ``IncompleteRead`` on a short body."""
        status, _, data = self._http.request("GET", f"/v2/blobs/{blob_id}/content", self._headers())
        if status != 200:
            raise _error(status, data)
        return data
