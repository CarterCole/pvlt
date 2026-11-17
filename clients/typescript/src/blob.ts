// pvlt blob encryption for browsers and Node, with WebCrypto only. Implements FORMAT.md sections 3, 4 and 4.2 for
// suite 0x0003 (AES-256-GCM), the one suite WebCrypto has. Suites 0x0001 and 0x0002 are for the server.
//
// The vault never sees a document: this is the code that encrypts it before upload and decrypts it after
// download. It must agree with the Rust implementation byte for byte; test/vectors.test.ts replays the shared
// known-answer vectors, and the smoke test uploads from here to a real server.
//
// Plaintext is released chunk by chunk as each chunk's tag verifies, but a stream is not good until it has ended
// without an error: if decryption throws, discard everything it yielded.

const encoder = new TextEncoder();

/** The domain-separation prefix `"PVLT-v1" ‖ 0x00`. */
const PREFIX = concat([encoder.encode("PVLT-v1"), new Uint8Array([0])]);

export const SUITE_AES_256_GCM = 0x0003;
export const HEADER_LEN = 104;
export const TAG_LEN = 16;
export const CHUNK_MIN = 1024;
export const CHUNK_MAX = 16 * 1024 * 1024;
export const CHUNK_DEFAULT = 65536;

/** Why something failed to encrypt or open. It never carries key material or plaintext. */
export class PvltError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PvltError";
  }
}

export interface BlobParams {
  /** 16 bytes, from the ticket's `domain_id`. */
  domainId: Uint8Array;
  /** 16 bytes, from the ticket's `object_id`. */
  objectId: Uint8Array;
  /** From the ticket's `dek_generation`. */
  dekGeneration: number;
  /** Plaintext bytes per chunk, from the ticket. */
  chunkSize: number;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function u64(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Padmé (FORMAT.md section 4.2): rounds `len` up so the length leaks only O(log log len) bits. */
export function padme(len: bigint): bigint {
  if (len < 2n) throw new PvltError("padme is defined for lengths of at least 2");
  const e = BigInt(len.toString(2).length - 1);
  const s = BigInt(e.toString(2).length - 1) + 1n;
  const mask = (1n << (e - s)) - 1n;
  return (len + mask) & ~mask;
}

/** The exact size of a sealed blob object for `dataLen` bytes of data, so an upload can be checked in advance. */
export function sealedLength(dataLen: number | bigint, chunkSize: number = CHUNK_DEFAULT): number {
  checkChunkSize(chunkSize);
  const total = padme(BigInt(dataLen) + 8n);
  const chunks = (total + BigInt(chunkSize) - 1n) / BigInt(chunkSize);
  return Number(BigInt(HEADER_LEN) + total + chunks * BigInt(TAG_LEN));
}

function checkChunkSize(chunkSize: number): void {
  if (!Number.isInteger(chunkSize) || chunkSize % 1024 !== 0 || chunkSize < CHUNK_MIN || chunkSize > CHUNK_MAX) {
    throw new PvltError("bad chunk size");
  }
}

function checkId(name: string, id: Uint8Array): void {
  if (!(id instanceof Uint8Array) || id.length !== 16) throw new PvltError(`${name} must be 16 bytes`);
}

/** HKDF-SHA-256 with the salt, a label, and a context (FORMAT.md section 3): the AEAD key and the commitment. */
async function derive(dek: Uint8Array, salt: Uint8Array, ctx: Uint8Array): Promise<{ ek: CryptoKey; ck: Uint8Array }> {
  if (dek.length !== 32) throw new PvltError("a data key is 32 bytes");
  // info = PREFIX ‖ label ‖ 0x00 ‖ u16(suite) ‖ ctx
  const suiteBytes = new Uint8Array([(SUITE_AES_256_GCM >> 8) & 0xff, SUITE_AES_256_GCM & 0xff]);
  const info = concat([PREFIX, encoder.encode("object"), new Uint8Array([0]), suiteBytes, ctx]);
  const ikm = await crypto.subtle.importKey("raw", dek, "HKDF", false, ["deriveBits"]);
  const okm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, ikm, 512));
  const ek = await crypto.subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  return { ek, ck: okm.slice(32, 64) };
}

/** `salt[0..7] ‖ u32(i) ‖ u8(last)`: the nonce for chunk `i` (FORMAT.md section 3). */
function nonce(salt: Uint8Array, i: number, last: boolean): Uint8Array {
  return concat([salt.slice(0, 7), u32(i), new Uint8Array([last ? 1 : 0])]);
}

function headerContext(p: BlobParams): Uint8Array {
  return concat([
    encoder.encode("PVLT"),
    new Uint8Array([1, 2]), // version 1, kind blob
    new Uint8Array([(SUITE_AES_256_GCM >> 8) & 0xff, SUITE_AES_256_GCM & 0xff]),
    p.domainId,
    p.objectId,
    u32(p.dekGeneration),
    u32(p.chunkSize),
  ]);
}

async function seal(ek: CryptoKey, iv: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, ek, plaintext));
}

async function open(ek: CryptoKey, iv: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, ek, sealed));
  } catch {
    // One failure for every cause: a wrong key, a changed byte, a reordered or truncated stream.
    throw new PvltError("open failed");
  }
}

type Source = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

/**
 * Encrypts a blob as a stream, in constant memory. Yields the 104-byte header, then sealed chunks.
 *
 * `dataLength` must be the exact number of bytes `source` will produce (it decides the padding and is checked
 * by the vault against the object's size). `salt` is for tests only: leave it out and 24 random bytes are drawn,
 * which is required: a salt must never repeat for one key.
 */
export async function* encryptStream(
  dek: Uint8Array,
  params: BlobParams,
  dataLength: number | bigint,
  source: Source,
  salt?: Uint8Array,
): AsyncGenerator<Uint8Array> {
  checkChunkSize(params.chunkSize);
  checkId("domainId", params.domainId);
  checkId("objectId", params.objectId);
  const s = salt ?? crypto.getRandomValues(new Uint8Array(24));
  if (s.length !== 24) throw new PvltError("a salt is 24 bytes");
  const len = BigInt(dataLength);
  const total = padme(len + 8n);
  const ctx = headerContext(params);
  const { ek, ck } = await derive(dek, s, ctx);
  const header = concat([ctx, s, ck]);
  yield header;

  const cs = params.chunkSize;
  let buf: Uint8Array = u64(len);
  let sealedBytes = 0n;
  let index = 0;
  let written = 0n;

  const flush = async function* (final: boolean): AsyncGenerator<Uint8Array> {
    // A full chunk is not the last unless it ends the stream.
    while (buf.length > cs || (buf.length === cs && sealedBytes + BigInt(cs) < total) || (final && buf.length > 0)) {
      const take = Math.min(buf.length, cs);
      const last = final && buf.length <= cs;
      yield await seal(ek, nonce(s, index, last), buf.slice(0, take), header);
      sealedBytes += BigInt(take);
      index += 1;
      buf = buf.slice(take);
    }
  };

  for await (const piece of source as AsyncIterable<Uint8Array>) {
    written += BigInt(piece.length);
    if (written > len) throw new PvltError("more data than was declared");
    buf = concat([buf, piece]);
    yield* flush(false);
  }
  if (written !== len) throw new PvltError("less data than was declared");
  const missing = total - sealedBytes - BigInt(buf.length);
  buf = concat([buf, new Uint8Array(Number(missing))]);
  yield* flush(true);
}

/** Encrypts a whole buffer. Returns the object: header then chunks. */
export async function encryptBlob(
  dek: Uint8Array,
  params: BlobParams,
  data: Uint8Array,
  salt?: Uint8Array,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const p of encryptStream(dek, params, data.length, [data], salt)) parts.push(p);
  return concat(parts);
}

/**
 * Decrypts a blob as a stream, in constant memory: one chunk at a time. Yields plaintext as each chunk verifies.
 * Throws a [PvltError] on a wrong key, a changed byte, truncation, reordering, extension or bad padding, and
 * the caller must then discard what it already received.
 */
export async function* decryptStream(dek: Uint8Array, source: Source): AsyncGenerator<Uint8Array> {
  let buf: Uint8Array = new Uint8Array(0);
  let state: { ek: CryptoKey; aad: Uint8Array; salt: Uint8Array; cs: number } | undefined;
  let index = 0;
  let declared: bigint | undefined;
  let opened = 0n;
  let returned = 0n;

  const emit = (plain: Uint8Array): Uint8Array => {
    let p = plain;
    if (declared === undefined) {
      if (p.length < 8) throw new PvltError("open failed");
      declared = new DataView(p.buffer, p.byteOffset, 8).getBigUint64(0, false);
      opened += 8n;
      p = p.slice(8);
    }
    const room = declared - returned;
    const take = Number(room < BigInt(p.length) ? room : BigInt(p.length));
    const data = p.slice(0, take);
    for (const b of p.slice(take)) if (b !== 0) throw new PvltError("open failed");
    returned += BigInt(take);
    opened += BigInt(p.length);
    return data;
  };

  for await (const piece of source as AsyncIterable<Uint8Array>) {
    buf = concat([buf, piece]);
    if (!state) {
      if (buf.length < HEADER_LEN) continue;
      const aad = buf.slice(0, HEADER_LEN);
      buf = buf.slice(HEADER_LEN);
      const view = new DataView(aad.buffer, aad.byteOffset, HEADER_LEN);
      if (!equal(aad.slice(0, 4), encoder.encode("PVLT")) || aad[4] !== 1 || aad[5] !== 2) {
        throw new PvltError("not a pvlt blob");
      }
      if (view.getUint16(6, false) !== SUITE_AES_256_GCM) throw new PvltError("this suite is for the server: WebCrypto has only 0x0003");
      const cs = view.getUint32(44, false);
      checkChunkSize(cs);
      const salt = aad.slice(48, 72);
      const { ek, ck } = await derive(dek, salt, aad.slice(0, 48));
      if (!equal(ck, aad.slice(72, 104))) throw new PvltError("open failed");
      state = { ek, aad, salt, cs };
    }
    const sealedChunk = state.cs + TAG_LEN;
    // More than one chunk is buffered, so the first is not the last.
    while (buf.length > sealedChunk) {
      const plain = await open(state.ek, nonce(state.salt, index, false), buf.slice(0, sealedChunk), state.aad);
      buf = buf.slice(sealedChunk);
      index += 1;
      const out = emit(plain);
      if (out.length > 0) yield out;
    }
  }
  if (!state || buf.length <= TAG_LEN) throw new PvltError("open failed");
  const plain = await open(state.ek, nonce(state.salt, index, true), buf, state.aad);
  const out = emit(plain);
  if (declared === undefined || declared + 8n < 2n || padme(declared + 8n) !== opened || returned !== declared) {
    throw new PvltError("open failed");
  }
  if (out.length > 0) yield out;
}

/** Decrypts a whole object and returns the data. */
export async function decryptBlob(dek: Uint8Array, object: Uint8Array): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const p of decryptStream(dek, [object])) parts.push(p);
  return concat(parts);
}

/** Decodes standard base64, as the API sends keys. */
export function fromBase64(text: string): Uint8Array {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decodes lowercase hex, as the API sends ids. */
export function fromHex(text: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/.test(text)) throw new PvltError("not hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
