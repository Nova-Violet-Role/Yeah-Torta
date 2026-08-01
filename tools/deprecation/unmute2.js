// MEASURE-ONLY: strip every deprecation suppression so the compiler reports the TRUE count.
//
// Fixes the design flaw in unmute.js, which greps for the needle it just removed and therefore
// aborts its own restore. This one restores from a manifest written at strip time, so the restore
// path does not depend on the state it is undoing.
//
// ============================================================================================
// CORRECTION 2026-08-01 -- THIS TOOL WAS UNDER-STRIPPING, AND EVERY NUMBER DOWNSTREAM WAS LOW.
//
// It matched the exact literal `@Suppress("DEPRECATION")` and nothing else. Kotlin's suppression
// names are CASE-INSENSITIVE, and the tree contains six `@Suppress("deprecation")` -- lowercase --
// guarding three whole functions in DnsRulesReceiver, an entire `object NetworkChecker`,
// ThemeUtils.setDayNightTheme and Utils.isServiceRunning.
//
// MEASURED, not reasoned: compile with the 36 uppercase stripped -> 34 warnings. Compile with the
// 6 lowercase ALSO stripped -> 79 warnings. FORTY-FIVE deprecations were masked, and every figure
// this session (34 total / 14 gated / 20 ungated) had been measured on a partially-muted tree
// while all five CI gates stayed green. This is the exact failure the empty-log FLOOR in depgate.js
// was written to prevent, arriving through a door the floor does not watch: the measurement DID
// happen, it was just taken through a filter nobody had checked.
//
// THE FIX IS WRITTEN FOR THE GENERAL CASE, NOT FOR TODAY'S SIX. Matching another literal would be
// the same defect one spelling later. It now parses the annotation:
//
//   * `@Suppress` and `@file:Suppress` (a file-level one mutes an entire file, and the old exact
//     match could never have seen it -- there are zero today, which is luck, not design)
//   * any case: "DEPRECATION", "deprecation", "Deprecation"
//   * whitespace inside the parentheses
//   * MULTI-ARGUMENT lists, where only the deprecation entry is removed and the others are kept.
//     Dropping the whole annotation would unmute unrelated diagnostics and pollute the very count
//     this tool exists to measure. Zero exist today; the handling is here so the first one added
//     does not silently corrupt a measurement.
//
// A count that can only go UP when the tool is fixed is the honest direction, but it is not
// self-correcting: nothing except this parser stands between a new spelling and a quiet undercount.
// unmute-conformance.js is the corpus that holds it.
// ============================================================================================
const fs = require("fs");
const path = require("path");
const ROOT = process.env.UNMUTE_ROOT || "libumdnscrypt/src/main";
const MANIFEST = process.env.UNMUTE_MANIFEST || "tools/deprecation/.unmute2.manifest.json";
const MARK = "// UNMUTED-FOR-MEASUREMENT";

/** Matches `@Suppress(...)` and `@file:Suppress(...)`, capturing the argument list. */
const SUPPRESS = /@(file:)?Suppress\s*\(([^)]*)\)/g;

/** Is this one argument a deprecation suppression, in any case and with any spacing? */
function isDeprecationArg(arg) {
  return /^\s*"\s*deprecation\s*"\s*$/i.test(arg);
}

/**
 * Remove every deprecation suppression from `src`.
 *
 * An annotation whose ONLY argument was the deprecation one becomes the marker comment, so the
 * line count is preserved and `restore` can verify nothing survived. An annotation with other
 * arguments keeps them.
 *
 * @returns {{out:string, removed:number}}
 */
function stripDeprecationSuppressions(src) {
  let removed = 0;
  const out = src.replace(SUPPRESS, (whole, filePrefix, args) => {
    const parts = args.split(",");
    const kept = parts.filter((a) => !isDeprecationArg(a));
    if (kept.length === parts.length) return whole;      // nothing to do
    removed += parts.length - kept.length;
    if (kept.length === 0) return MARK;
    return "@" + (filePrefix || "") + "Suppress(" + kept.join(",").trim() + ")";
  });
  return { out, removed };
}

module.exports = { stripDeprecationSuppressions, isDeprecationArg, MARK };

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".kt")) out.push(p);
  }
  return out;
}

// Only act as a CLI when RUN, not when REQUIRED. unmute-conformance.js imports
// stripDeprecationSuppressions to test the real function rather than a copy of it, and without
// this guard the import would fall through to the usage message and exit 64.
const mode = require.main === module ? process.argv[2] : null;

if (mode === "strip") {
  const files = walk(ROOT);
  const manifest = [];
  let totalRemoved = 0;
  for (const f of files) {
    const orig = fs.readFileSync(f, "utf8");
    const { out, removed } = stripDeprecationSuppressions(orig);
    if (removed === 0) continue;
    const bak = f + ".unmute2.bak";
    fs.writeFileSync(bak, orig, "utf8");
    fs.writeFileSync(f, out, "utf8");
    manifest.push({ file: f, bak, removed });
    totalRemoved += removed;
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 1), "utf8");

  // A strip that removed nothing is a BROKEN MEASUREMENT, not a clean tree -- the same defect as
  // a gate passing on an empty log. If the repo ever genuinely reaches zero suppressions this must
  // be lowered deliberately, in a commit that says so, rather than discovered by a silent pass.
  const FLOOR = Number(process.env.UNMUTE_FLOOR !== undefined ? process.env.UNMUTE_FLOOR : 30);
  console.log("  stripped " + totalRemoved + " suppression(s) in " + manifest.length + " file(s)");
  if (totalRemoved < FLOOR) {
    console.log("  FAIL: only " + totalRemoved + " removed (floor " + FLOOR + "). Either the tree");
    console.log("        changed a great deal, or the matcher stopped matching a spelling.");
    process.exit(6);
  }

  // Independent verification: NO deprecation suppression may survive, in any spelling.
  let survivors = 0;
  for (const f of walk(ROOT)) {
    const t = fs.readFileSync(f, "utf8");
    let m;
    const re = new RegExp(SUPPRESS.source, "g");
    while ((m = re.exec(t)) !== null) {
      if (m[2].split(",").some(isDeprecationArg)) {
        console.log("  SURVIVING SUPPRESSION: " + f + "  " + m[0]);
        survivors++;
      }
    }
  }
  if (survivors > 0) {
    console.log("  FAIL: " + survivors + " deprecation suppression(s) survived the strip.");
    process.exit(7);
  }
  console.log("  verified: 0 deprecation suppressions remain");
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

if (require.main === module) {
  console.log("usage: node unmute2.js strip|restore");
  process.exit(64);
}
