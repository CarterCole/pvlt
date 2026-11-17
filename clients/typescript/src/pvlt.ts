// A small client for the pvlt /v2 API: facts, and blobs with client-side encryption. Uses `fetch` and WebCrypto,
// so it runs in browsers and in Node 22+.
//
// Pre-alpha. Request tokens are minted by *your* backend (see docs/RUNNING.md); this client only presents one. A
// browser should get a token for one blob from your backend, never hold a long-lived credential.

import { decryptStream, encryptStream, fromBase64, fromHex, sealedLength, PvltError } from "./blob.ts";

export { PvltError } from "./blob.ts";
export * from "./blob.ts";

/** A source of request tokens. Called for every request, because tokens are short-lived. */
export type TokenSource = string | (() => string | Promise<string>);

export interface ClientOptions {
  /** For example `https://vault.example.com:8443`. */
  baseUrl: string;
  token: TokenSource;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export interface BlobTicket {
  id: string;
  suite: number;
  chunk_size: number;
  domain_id: string;
  object_id: string;
  dek_generation: number;
  dek: string;
  size: number;
  sealed_size: number;
  upload: { method: string; url: string; via: "bucket" | "vault"; expires_in: number };
}

export interface BlobAccess {
  id: string;
  type: string;
  suite: number;
  chunk_size: number;
  domain_id: string;
  object_id: string;
  dek_generation: number;
  dek: string;
  size: number;
  download: { method: string; url: string; via: "bucket" | "vault"; expires_in: number };
}

/** An HTTP error from the vault: a status and the stable code (`denied`, `shredded`, `not_found`, ...). */
export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(`${status} ${code}: ${message}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export class PvltClient {
  readonly #base: string;
  readonly #token: TokenSource;
  readonly #fetch: typeof fetch;

  constructor(options: ClientOptions) {
    this.#base = options.baseUrl.replace(/\/+$/, "");
    this.#token = options.token;
    this.#fetch = options.fetch ?? fetch;
  }

  async #headers(extra: Record<string, string> = {}): Promise<Record<string, string>> {
    const token = typeof this.#token === "function" ? await this.#token() : this.#token;
    return { Authorization: `Bearer ${token}`, ...extra };
  }

  async #json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.#fetch(this.#base + path, {
      method,
      headers: await this.#headers(body === undefined ? {} : { "Content-Type": "application/json" }),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) {
      let code = "error";
      let message = text;
      try {
        const j = JSON.parse(text);
        code = j.error ?? code;
        message = j.message ?? message;
      } catch {
        // not JSON: keep the text
      }
      throw new ApiError(res.status, code, message);
    }
    return text === "" ? (undefined as T) : (JSON.parse(text) as T);
  }

  /** Stores a small fact. Returns its id. */
  async createFact(fact: { type: string; scope: string; subject?: string; value: string; retain_days?: number }): Promise<string> {
    return (await this.#json<{ id: string }>("POST", "/v2/facts", fact)).id;
  }

  /** Reads a small fact. */
  async readFact(id: string): Promise<{ id: string; type: string; value?: string; value_b64?: string }> {
    return this.#json("GET", `/v2/facts/${id}`);
  }

  /** Shreds a fact or a blob. */
  async shred(id: string): Promise<{ outcome: string }> {
    return this.#json("DELETE", `/v2/facts/${id}`);
  }

  /** Asks for a blob: a key and an upload address. The key is shown once. */
  async createBlob(blob: {
    type: string;
    scope: string;
    subject?: string;
    size: number;
    chunk_size?: number;
    retain_days?: number;
  }): Promise<BlobTicket> {
    return this.#json("POST", "/v2/blobs", blob);
  }

  /**
   * Encrypts `data` with a new blob's key, uploads the ciphertext (straight to the bucket if it gave a presigned
   * URL, through the vault otherwise), and has the vault check and complete it. Returns the blob id.
   */
  async uploadBlob(
    meta: { type: string; scope: string; subject?: string; retain_days?: number; chunk_size?: number },
    data: Uint8Array,
  ): Promise<string> {
    const ticket = await this.createBlob({ ...meta, size: data.length });
    const dek = fromBase64(ticket.dek);
    const parts: Uint8Array[] = [];
    for await (const p of encryptStream(
      dek,
      {
        domainId: fromHex(ticket.domain_id),
        objectId: fromHex(ticket.object_id),
        dekGeneration: ticket.dek_generation,
        chunkSize: ticket.chunk_size,
      },
      data.length,
      [data],
    ))
      parts.push(p);
    const object = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      object.set(p, at);
      at += p.length;
    }
    if (object.length !== ticket.sealed_size || object.length !== sealedLength(data.length, ticket.chunk_size)) {
      throw new PvltError("the encrypted size is not the size the vault expects");
    }
    if (ticket.upload.via === "bucket") {
      // A presigned URL carries its own authorization: send no vault token to the bucket.
      const res = await this.#fetch(ticket.upload.url, { method: "PUT", body: object });
      if (!res.ok) throw new ApiError(res.status, "upload_failed", "the bucket refused the upload");
    } else {
      const res = await this.#fetch(this.#base + ticket.upload.url, {
        method: "PUT",
        headers: await this.#headers(),
        body: object,
      });
      if (!res.ok) throw new ApiError(res.status, "upload_failed", await res.text());
    }
    await this.#json("POST", `/v2/blobs/${ticket.id}/complete`);
    return ticket.id;
  }

  /** Opens a blob: the vault writes the disclosure, hands over the key, and this decrypts the download. */
  async downloadBlob(id: string): Promise<Uint8Array> {
    const access = await this.#json<BlobAccess>("GET", `/v2/blobs/${id}/access`);
    const res =
      access.download.via === "bucket"
        ? await this.#fetch(access.download.url)
        : await this.#fetch(this.#base + access.download.url, { headers: await this.#headers() });
    if (!res.ok || !res.body) throw new ApiError(res.status, "download_failed", "could not download the object");
    const out: Uint8Array[] = [];
    const source = res.body as unknown as AsyncIterable<Uint8Array>;
    for await (const p of decryptStream(fromBase64(access.dek), source)) out.push(p);
    const data = new Uint8Array(out.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of out) {
      data.set(p, at);
      at += p.length;
    }
    return data;
  }
}
