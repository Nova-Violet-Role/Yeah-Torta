// MEASURE-ONLY: strip every @Suppress("DEPRECATION") that is NOT one of the narrowly-scoped ones
// added this session, so the compiler reports the TRUE deprecation count.
//
// Fixes the design flaw in unmute.js, which greps for the needle it just removed and therefore
// aborts its own restore. This one restores from a manifest written at strip time, so the restore
// path does not depend on the state it is undoing.
const fs = require("fs");
const path = require("path");
const ROOT = "libumdnscrypt/src/main";
const MANIFEST = "tools/deprecation/.unmute2.manifest.json";
const MARK = "// UNMUTED-FOR-MEASUREMENT";

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".kt")) out.push(p);
  }
  return out;
}

const mode = process.argv[2];

if (mode === "strip") {
  const files = walk(ROOT);
  const manifest = [];
  for (const f of files) {
    const orig = fs.readFileSync(f, "utf8");
    if (!orig.includes('@Suppress("DEPRECATION")')) continue;
    const bak = f + ".unmute2.bak";
    fs.writeFileSync(bak, orig, "utf8");
    const stripped = orig.split('@Suppress("DEPRECATION")').join(MARK);
    fs.writeFileSync(f, stripped, "utf8");
    manifest.push({ file: f, bak });
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 1), "utf8");
  console.log("  stripped in " + manifest.length + " files; manifest written");
  process.exit(0);
}

if (mode === "restore") {
  if (!fs.existsSync(MANIFEST)) { console.log("  NO MANIFEST -- nothing to restore, or it was lost"); process.exit(1); }
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  let restored = 0, missing = 0;
  for (const { file, bak } of manifest) {
    if (!fs.existsSync(bak)) { console.log("  MISSING BACKUP: " + bak); missing++; continue; }
    fs.writeFileSync(file, fs.readFileSync(bak, "utf8"), "utf8");
    fs.unlinkSync(bak);
    restored++;
  }
  fs.unlinkSync(MANIFEST);
  // Independent verification, not a claim: no marker may survive anywhere.
  let residual = 0;
  for (const f of walk(ROOT)) if (fs.readFileSync(f, "utf8").includes(MARK)) { console.log("  RESIDUAL MARKER: " + f); residual++; }
  console.log("  restored=" + restored + " missingBackups=" + missing + " residualMarkers=" + residual);
  process.exit(missing || residual ? 2 : 0);
}

console.log("usage: node unmute2.js strip|restore");
process.exit(64);
