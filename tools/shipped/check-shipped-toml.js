// The shipped-asset binding, ENFORCED.
//
// rust/torta_core/src/resolver/dnscrypt_config.rs documents a test that parses
// `shipped/dnscrypt-proxy.toml` and calls it "the exact bytes shipped inside assets/dnscrypt.zip",
// so that the round-trip test runs against "the bytes that reach a real device". The comment also
// named `tools/check-shipped-toml.sh` as the thing that "fails if the two ever diverge".
//
// THAT CHECKER DID NOT EXIST. Measured 2026-08-01: no such file anywhere in the tree. And the two
// copies HAD ALREADY DIVERGED -- three lines, the project-wide tordnscrypt -> libumdnscrypt rename,
// applied to the text copy and missed inside the binary zip because grep cannot see into it.
//
// That is the exact overclaim this repo hunts: a test whose comment says it binds to the real
// artifact while it binds to a stale copy. The Rust test was green throughout, because it was
// testing a file nobody shipped.
//
// This is that checker, for real. It is JavaScript rather than shell because this project does not
// use .sh files.
//
// It reads the zip directly -- no unzip binary, no temp dir -- so it cannot pass by failing to
// find the archive.
const fs = require("fs");
const zlib = require("zlib");

const ZIP = "libumdnscrypt/src/main/assets/dnscrypt.zip";
const ENTRY = "app_data/dnscrypt-proxy/dnscrypt-proxy.toml";
const SHIPPED = "rust/torta_core/src/resolver/shipped/dnscrypt-proxy.toml";

function die(msg, code) { console.log("  FAIL: " + msg); process.exit(code); }

for (const p of [ZIP, SHIPPED]) if (!fs.existsSync(p)) die("missing " + p, 2);

/** Minimal zip reader: locate ENTRY via the central directory and inflate it. */
function readZipEntry(zipPath, entryName) {
  const buf = fs.readFileSync(zipPath);
  // End of central directory record: signature 0x06054b50, scanned from the tail.
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 22 - 65536; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("no end-of-central-directory found -- not a zip?");
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  let found = null, seen = 0;
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error("bad central directory header at " + off);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const cmtLen = buf.readUInt16LE(off + 32);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString("utf8");
    if (name === entryName) { found = { lho: buf.readUInt32LE(off + 42), method: buf.readUInt16LE(off + 10), csize: buf.readUInt32LE(off + 20) }; seen++; }
    off += 46 + nameLen + extraLen + cmtLen;
  }
  if (seen !== 1) throw new Error("expected exactly 1 '" + entryName + "' in the zip, found " + seen);
  // Local file header: name/extra lengths can differ from the central copy.
  const lho = found.lho;
  if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error("bad local file header");
  const lnameLen = buf.readUInt16LE(lho + 26);
  const lextraLen = buf.readUInt16LE(lho + 28);
  const start = lho + 30 + lnameLen + lextraLen;
  const raw = buf.slice(start, start + found.csize);
  return found.method === 0 ? raw : zlib.inflateRawSync(raw);
}

let inZip;
try { inZip = readZipEntry(ZIP, ENTRY); }
catch (e) { die("could not read " + ENTRY + " from " + ZIP + ": " + e.message, 3); }

const onDisk = fs.readFileSync(SHIPPED);

// A FLOOR on the content, so the check cannot pass on an empty or truncated entry -- the same
// broken-measurement hazard the deprecation gate has. The real file is ~4 KB.
if (inZip.length < 1000) die("the zip entry is only " + inZip.length + " bytes -- broken measurement, not a match", 5);

if (Buffer.compare(inZip, onDisk) === 0) {
  console.log("  PASS: " + ENTRY + " in the zip is byte-identical to " + SHIPPED);
  console.log("        (" + inZip.length + " bytes)");
  process.exit(0);
}

console.log("  FAIL: the SHIPPED asset and the Rust test corpus have diverged.");
console.log("        zip entry : " + inZip.length + " bytes");
console.log("        shipped/  : " + onDisk.length + " bytes");
console.log("  The Rust test `the_shipped_config_round_trips_through_the_live_model` claims to run");
console.log("  against the bytes that reach a real device. While these differ, it does not.");
const a = inZip.toString("utf8").split("\n"), b = onDisk.toString("utf8").split("\n");
let shown = 0;
for (let i = 0; i < Math.max(a.length, b.length) && shown < 10; i++) {
  if (a[i] !== b[i]) { console.log("    line " + (i + 1) + "\n      zip: " + (a[i] ?? "<eof>") + "\n      src: " + (b[i] ?? "<eof>")); shown++; }
}
process.exit(1);
