// Classify each deprecation warning (measured with the suppressions stripped) as either
//   GATED   -- reachable only on API levels below the replacement's minimum, so it is REQUIRED by
//              minSdk 21 and is not a defect, or
//   UNGATED -- runs on every device; the real backlog.
//
// WHY v2 EXISTS. v1 decided this by looking at the 15 lines ABOVE the warning for a
// Build.VERSION.SDK_INT test. That misses the commonest correct shape by design: a legacy helper
// whose version test lives at its CALLER. It scored WireCakeInuManager's resolveService as ungated
// immediately after that call had been correctly gated. Reporting a stale number is bad; reporting
// one that moves the WRONG WAY when you fix something is worse.
//
// CORRECTION 2026-08-01 -- this comment used to continue "...and it scores ModulesReceiver's 13
// legacy broadcast lines as ungated for the same reason", and I repeated that in commit 7b8c55b0
// as "13 ModulesReceiver + 1 WireCakeInuManager are caller-gated, leaving 7 genuinely ungated".
//
// THAT WAS WRONG, AND THE TOOL WAS RIGHT. I read the source instead of asserting it
// (ModulesReceiver.kt:291-301):
//
//     private fun registerConnectivityChanges() {
//         if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//             try { listenNetworkChanges() }
//             catch (e: Exception) { listenConnectivityChanges() }   // legacy, on a MODERN device
//         } else { listenConnectivityChanges() }
//     }
//
// The legacy listener is reachable on EVERY device through the catch -- a deliberate defensive
// fallback, and correct as code. So those call sites genuinely are not gated, and the five
// LEGACY_* constants at :1329-1341 are not even inside a function: they are top-level property
// initialisers evaluated at class-init on every device.
//
// The classifier's conservative direction (unresolvable => UNGATED) is what stopped me from
// absolving 14 usages by hand on a reading that was simply not true. That is the whole argument
// for fail-loud: my confident manual correction was the unreliable instrument here, not the tool.
//
// SECOND CORRECTION, same day: the honest count is 20, not 19 and certainly not 7. The fixture
// corpus (gated-conformance.js) found that the SDK_INT window crossed function boundaries, so
// ExtendedDialogFragment.kt:89 `retainInstance` -- inside onDestroyView() declared at :86 -- was
// absolved by an SDK_INT test at :79 that belongs to a DIFFERENT function which closed at :83.
// That was the one branch of the walk capable of marking something safe without evidence, and it
// had been quietly shrinking the backlog. The code did not get worse; the instrument got honest.
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
const { parseWarningLine } = require(__dirname + "/parse.js");
const path = require("path");

// DEPGATE_ROOT: injectable so the call-graph walk can be run against fixtures. See depgate.js.
const ROOT = process.env.DEPGATE_ROOT || "libumdnscrypt/src/main";
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

// The call-graph walk lives in callgraph.js -- the SAME copy depgate.js uses, so the reporter and
// the gate can never disagree about which usages are gated. They previously held separate copies
// that had already drifted, and the shared one carries a real fix: the SDK_INT window no longer
// crosses function boundaries. See callgraph.js.
const { isGated: isGatedRaw } = require(__dirname + "/callgraph.js");
const isGated = (file, line, depth, seen) => isGatedRaw(text, file, line, depth, seen);

// ---- read the warnings ------------------------------------------------------------------------
const rows = [];
for (const l of fs.readFileSync(LOG, "utf8").split(/\r?\n/)) {
  // Parsing lives in parse.js -- the SAME copy depgate.js uses, so the classifier and the gate can
  // never disagree about what a warning line means. They previously held identical inline regexes;
  // identical today is not the same as identical tomorrow.
  //
  // Resolve by BASENAME from the on-disk index. Do NOT trust the percent-decoded URL as a path:
  // this repo's directory name contains a non-ASCII character and decoding it yields a path that
  // will not open, which an earlier version hid behind catch/continue and reported as a backlog of
  // zero.
  const parsed = parseWarningLine(l);
  if (!parsed) continue;
  rows.push({ base: parsed.base, line: parsed.line, msg: parsed.message });
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
