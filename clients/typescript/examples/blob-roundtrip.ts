// Uploads a file as an encrypted blob and downloads it again, checking that the bytes match. Used by
// scripts/smoke.sh against a real server and bucket.
//
//   node examples/blob-roundtrip.ts <base-url> <token> <file>
//
// Set NODE_EXTRA_CA_CERTS to trust a self-signed certificate.
import { readFileSync } from "node:fs";
import { PvltClient } from "../src/pvlt.ts";

const [baseUrl, token, file] = process.argv.slice(2);
if (!baseUrl || !token || !file) {
  console.error("usage: node blob-roundtrip.ts <base-url> <token> <file>");
  process.exit(2);
}
const data = new Uint8Array(readFileSync(file));
const client = new PvltClient({ baseUrl, token });
const id = await client.uploadBlob({ type: "identity", scope: "kyc-doc:ts", subject: "user:ts" }, data);
const back = await client.downloadBlob(id);
if (back.length !== data.length || !back.every((b, i) => b === data[i])) {
  console.error("MISMATCH");
  process.exit(1);
}
console.log(`ok ${id} ${data.length}`);
