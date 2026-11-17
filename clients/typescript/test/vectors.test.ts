// Replays the shared known-answer vectors (spec/vectors/blob.json) through the WebCrypto implementation, and
// checks that streaming, splitting and tampering behave as the Rust implementation does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  PvltError,
  decryptBlob,
  decryptStream,
  encryptBlob,
  encryptStream,
  fromHex,
  padme,
  sealedLength,
  toHex,
} from "../src/blob.ts";

const vectors = JSON.parse(readFileSync(new URL("../../../spec/vectors/blob.json", import.meta.url), "utf8")).vectors;
const gcm = vectors.filter((v: { suite: number }) => v.suite === 3);
const other = vectors.filter((v: { suite: number }) => v.suite !== 3);

function params(v: Record<string, string | number>) {
  return {
    domainId: fromHex(v.domain_id as string),
    objectId: fromHex(v.object_id as string),
    dekGeneration: v.dek_generation as number,
    chunkSize: v.chunk_size as number,
  };
}

test("there are four AES-256-GCM vectors and the others are the server's suites", () => {
  assert.equal(gcm.length, 4);
  assert.equal(other.length, 8);
});

test("every AES-256-GCM vector encrypts to exactly the expected object", async () => {
  for (const v of gcm) {
    const got = await encryptBlob(fromHex(v.dek), params(v), fromHex(v.data), fromHex(v.salt));
    assert.equal(toHex(got), v.expected.object, v.name);
  }
});

test("every AES-256-GCM vector decrypts to its data, however the object is cut", async () => {
  for (const v of gcm) {
    const object = fromHex(v.expected.object);
    assert.deepEqual(await decryptBlob(fromHex(v.dek), object), fromHex(v.data), v.name);
    for (const step of [1, 7, 100, 1040, object.length]) {
      const pieces: Uint8Array[] = [];
      for (let i = 0; i < object.length; i += step) pieces.push(object.slice(i, i + step));
      const out: number[] = [];
      for await (const p of decryptStream(fromHex(v.dek), pieces)) out.push(...p);
      assert.deepEqual(Uint8Array.from(out), fromHex(v.data), `${v.name} step ${step}`);
    }
  }
});

test("the server's other suites are refused, not misread", async () => {
  for (const v of other) {
    await assert.rejects(decryptBlob(fromHex(v.dek), fromHex(v.expected.object)), PvltError, v.name);
  }
});

test("padme and sealedLength match the lengths in the vectors", () => {
  for (const v of gcm) {
    assert.equal(Number(padme(BigInt(v.data.length / 2) + 8n)), v.expected.padded_len, v.name);
    assert.equal(sealedLength(v.data.length / 2, v.chunk_size), v.expected.object.length / 2, v.name);
  }
  assert.throws(() => padme(1n), PvltError);
  // A few values worked out by hand: 8 → 8, 5008 → 5120, 100000 → 100352.
  assert.equal(padme(8n), 8n);
  assert.equal(padme(5008n), 5120n);
  assert.equal(padme(100000n), 100352n);
});

function bytes(n: number, seed = 1): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out[i] = x >> 16;
  }
  return out;
}

const KEY = new Uint8Array(32).fill(0x11);
const P = { domainId: new Uint8Array(16).fill(0x22), objectId: new Uint8Array(16).fill(0x33), dekGeneration: 3, chunkSize: 1024 };

test("round trips for lengths on and around every chunk boundary, however the data is cut going in", async () => {
  for (const len of [0, 1, 7, 8, 9, 1015, 1016, 1017, 2039, 2040, 2041, 2500, 10_000]) {
    const data = bytes(len, len + 1);
    const whole = await encryptBlob(KEY, P, data, new Uint8Array(24).fill(9));
    assert.equal(whole.length, sealedLength(len, 1024), `len ${len}`);
    for (const step of [1, 333, 1024, 100_000]) {
      const pieces: Uint8Array[] = [];
      for (let i = 0; i < data.length; i += step) pieces.push(data.slice(i, i + step));
      const out: number[] = [];
      for await (const p of encryptStream(KEY, P, len, pieces, new Uint8Array(24).fill(9))) out.push(...p);
      assert.deepEqual(Uint8Array.from(out), whole, `len ${len} step ${step}`);
    }
    assert.deepEqual(await decryptBlob(KEY, whole), data, `len ${len}`);
  }
});

test("the encryptor enforces the declared length and uses a fresh salt each time", async () => {
  await assert.rejects(collect(encryptStream(KEY, P, 5, [bytes(10)])), PvltError);
  await assert.rejects(collect(encryptStream(KEY, P, 20, [bytes(10)])), PvltError);
  const a = await encryptBlob(KEY, P, bytes(10));
  const b = await encryptBlob(KEY, P, bytes(10));
  assert.notDeepEqual(a.slice(48, 72), b.slice(48, 72), "two encryptions drew the same salt");
  await assert.rejects(collect(encryptStream(KEY, { ...P, chunkSize: 1000 }, 1, [bytes(1)])), PvltError);
  await assert.rejects(collect(encryptStream(KEY, { ...P, domainId: new Uint8Array(3) }, 1, [bytes(1)])), PvltError);
});

async function collect(gen: AsyncGenerator<Uint8Array>): Promise<void> {
  for await (const _ of gen) void _;
}

test("a changed byte anywhere, truncation, reordering, extension and the wrong key are all refused", async () => {
  const data = bytes(5000);
  const object = await encryptBlob(KEY, P, data, new Uint8Array(24).fill(1));
  const bad = (o: Uint8Array, key = KEY) => assert.rejects(decryptBlob(key, o), PvltError);

  for (const at of [0, 5, 6, 44, 60, 80, 103, 104, 500, 1500, object.length - 1]) {
    const x = object.slice();
    x[at] = (x[at] as number) ^ 1;
    await bad(x);
  }
  for (const cut of [1, 16, 1040, object.length - 104, object.length - 103]) await bad(object.slice(0, object.length - cut));
  await bad(object.slice(0, 50));
  await bad(new Uint8Array(0));

  const sealed = 1024 + 16;
  const chunks = Math.ceil((object.length - 104) / sealed);
  const c = (i: number) => object.slice(104 + i * sealed, 104 + (i + 1) * sealed);
  const swapped = [object.slice(0, 104), c(1), c(0), ...Array.from({ length: chunks - 3 }, (_, i) => c(i + 2)), object.slice(104 + (chunks - 1) * sealed)];
  await bad(Uint8Array.from(swapped.flatMap((p) => Array.from(p))));
  await bad(Uint8Array.from([...object, ...c(0)]));
  await bad(object.slice(0, 104 + (chunks - 1) * sealed), KEY);
  await bad(object, new Uint8Array(32).fill(0x12));
});

test("a stream that stops early never finishes cleanly", async () => {
  const data = bytes(8000);
  const object = await encryptBlob(KEY, P, data);
  const gen = decryptStream(KEY, [object.slice(0, 104 + 3 * 1040 + 5)]);
  const got: number[] = [];
  await assert.rejects(async () => {
    for await (const p of gen) got.push(...p);
  }, PvltError);
  assert.ok(got.length > 0 && got.length < data.length, "verified chunks were released before the failure, which the caller must discard");
});
