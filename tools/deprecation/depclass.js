// Classify each deprecation warning (measured with the suppressions stripped) as either
//   GATED   -- reachable only on API levels below the replacement's minimum, so it is REQUIRED by
//              minSdk 21 and is not a defect, or
//   UNGATED -- runs on every device; the real backlog.
//
// WHY v2 EXISTS. v1 decided this by looking at the 15 lines ABOVE the warning for a
// Build.VERSION.SDK_INT test. That misses the commonest correct shape by design: a legacy helper
// whose version test lives at its CALLER. It scored WireCakeInuManager's resolveService as ungated
// immediately after that call had been correctly gated, and it scores ModulesReceiver's 13 legacy
// broadcast lines as ungated for the same reason. Reporting a stale number is bad; reporting one
// that moves the WRONG WAY when you fix something is worse.
//
// v2 adds one level of call-graph reasoning:
//   1. find the function enclosing the warning
//   2. find every call site of that function across the module
//   3. if EVERY call site is itself inside an SDK_INT branch (or inside a function that is), the
//      warning is gated
// One level of indirection, applied transitively up to a small depth. Not a real static analysis --
// it cannot see through interfaces, callbacks or reflection -- so the limit is stated in the output
// rather than hidden, and anything it cannot resolve is counted as UNGATED (fail-loud, never
// fail-quiet: an unclassifiable warning must never be silently absolved).
const fs = require("fs");
const path = require("path");

const ROOT = "libumdnscrypt/src/main";
const LOG = process.argv[2];
if (!LOG || !fs.existsSync(LOG)) { console.log("usage: depclass.js <compile-log>"); process.exit(2); }

// ---- index every .kt by basename AND keep its text -------------------------------------------
const files = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (e.name !== "build" && e.name !== ".git") walk(p); }
    else if (e.name.endsWith(".kt")) files.push(p);
  }
})(ROOT);
const byBase = new Map();
const text = new Map();
for (const p of files) {
  byBase.set(path.basename(p), p);
  text.set(p, fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n").split("\n"));
}

const FUN = /^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public |private |internal |protected )?(?:override |suspend |inline |open |abstract )*fun\s+(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)/;
const SDK = /Build\.VERSION\.SDK_INT\s*(?:>=|>|<|<=)/;

const indentOf = (s) => (s.match(/^\s*/) || [""])[0].length;

/**
 * The name of the function STRUCTURALLY enclosing `line` (1-based), or null.
 *
 * Indentation-aware, and that is not a nicety. Scanning upward for the nearest `fun` picks up
 * overrides declared inside object expressions, which are nested DEEPER than the statement they
 * sit above. Measured: for `nsd.resolveService(...)` the naive scan returned `onServiceResolved`
 * -- an override of an anonymous NsdManager.ResolveListener -- whose call sites are the framework's
 * and therefore textually invisible, so the warning was scored UNGATED when its real enclosing
 * function is gated at the caller. Requiring the declaration to be less indented than the statement
 * selects the member that actually contains it.
 */
function enclosingFun(src, line) {
  const want = indentOf(src[line - 1] || "");
  for (let i = line - 1; i >= 0; i--) {
    const m = src[i] && src[i].match(FUN);
    if (m && indentOf(src[i]) < want) return { name: m[1], at: i + 1 };
  }
  return null;
}

/** Is `line` within `win` lines below an SDK_INT test, inside the same file? */
function gatedAt(src, line, win = 15) {
  return SDK.test(src.slice(Math.max(0, line - 1 - win), line).join("\n"));
}

/** Every call site of `name` across the module, as {file, line}. */
function callSites(name) {
  const re = new RegExp("(?:^|[^A-Za-z0-9_.])" + name + "\\s*\\(");
  const out = [];
  for (const [p, src] of text) {
    for (let i = 0; i < src.length; i++) {
      if (!re.test(src[i])) continue;
      if (FUN.test(src[i])) continue;              // the declaration itself
      out.push({ file: p, line: i + 1 });
    }
  }
  return out;
}

/** Gated directly, or gated at every call site (transitively, bounded depth). */
function isGated(file, line, depth, seen) {
  const src = text.get(file);
  if (!src) return false;
  if (gatedAt(src, line)) return true;
  if (depth <= 0) return false;
  const fn = enclosingFun(src, line);
  if (!fn) return false;
  const key = file + "#" + fn.name;
  if (seen.has(key)) return false;                 // recursion guard
  seen.add(key);
  const sites = callSites(fn.name);
  if (sites.length === 0) return false;            // no caller found -> cannot absolve it
  return sites.every((s) => isGated(s.file, s.line, depth - 1, seen));
}

// ---- read the warnings ------------------------------------------------------------------------
const rows = [];
for (const l of fs.readFileSync(LOG, "utf8").split(/\r?\n/)) {
  const m = l.match(/w: file:\/\/\/(\S+?\.kt):(\d+):\d+\s+(.*)$/);
  if (!m) continue;
  // Resolve by BASENAME from the on-disk index. Do NOT trust the percent-decoded URL: this repo's
  // path contains a non-ASCII character and decoding it yields a path that will not open, which an
  // earlier version hid behind catch/continue and reported as a backlog of zero.
  const base = decodeURIComponent(m[1]).split(/[\\/]/).pop();
  rows.push({ base, line: +m[2], msg: m[3] });
}

let gated = 0, unresolved = 0;
const ungated = [];
for (const r of rows) {
  const p = byBase.get(r.base);
  if (!p) { unresolved++; console.log("  UNRESOLVED PATH: " + r.base); continue; }
  if (isGated(p, r.line, 3, new Set())) gated++; else ungated.push(r);
}

console.log("  total=" + rows.length + "  unresolved=" + unresolved + "  (unresolved MUST be 0)");
console.log("  GATED (legacy branch required by minSdk 21): " + gated);
console.log("  UNGATED (runs on every device):              " + ungated.length);
for (const r of ungated) console.log("     " + r.base + ":" + r.line + "  " + r.msg.slice(0, 52));
console.log("  LIMIT: one-level-transitive, depth 3, textual call matching. No interfaces,");
console.log("         callbacks or reflection. Unresolvable => counted UNGATED, never absolved.");
process.exit(unresolved > 0 ? 3 : 0);
