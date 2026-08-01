// Deprecation regression gate.
//
// The problem this solves: this session drove the ungated-deprecation backlog down and wrote the
// remaining items into commit messages. Commit messages do not fail a build. Without a gate the
// count silently grows again and the next person inherits a number nobody is measuring.
//
// WHAT IT ASSERTS, and why it is shaped this way:
//
//   observed[file, symbol] <= baseline[file, symbol]   for every key, and no NEW key at all.
//
// A CEILING, not an equality. A spec that pins the exact present state forbids a correct future:
// fixing a deprecation would turn the build RED on a good commit, and the obvious repair would be
// to weaken the gate, destroying the coverage. So removing a deprecated usage PASSES and is
// reported as slack to be reclaimed; adding one FAILS.
//
// KEYED BY (basename, deprecated symbol), NOT BY LINE. Line numbers move under any edit, and a
// line-keyed baseline would fail on a pure reformat while missing a real regression that shifted
// by one line. The symbol is read out of the compiler's own message text.
//
// Counts are per key because a symbol legitimately appears several times in one file (NetworkInfo
// occurs 4x in the legacy broadcast handler).
const fs = require("fs");
const { parseWarningLine, keyOf } = require(__dirname + "/parse.js");
const path = require("path");

const MODE = process.argv[2];                    // "check" | "write"
const LOG = process.argv[3];
// DEPGATE_BASELINE / DEPGATE_ROOT / DEPGATE_FLOOR are injection points for the isGated corpus
// (gated-conformance.js). Production sets none of them and gets the committed values below.
const BASE = process.env.DEPGATE_BASELINE || "tools/deprecation/deprecation-baseline.json";

if (!LOG || !fs.existsSync(LOG)) { console.log("usage: depgate.js <check|write> <compile-log>"); process.exit(2); }

// ---- reuse depclass's classification -----------------------------------------------------------
// DEPGATE_ROOT exists so the isGated call-graph walk can be exercised against FIXTURES.
//
// isGated decides 15 of the 34 warnings -- whether a deprecated call is a required minSdk-21
// legacy branch or a real backlog item. It had no corpus and no theorem: a bug in it moves usages
// between GATED and UNGATED silently, and the totals still add up to 34 either way.
//
// Hardcoding the root made it untestable, so the honest fix is to make the root injectable rather
// than to re-implement the walk in a test (two copies of a classifier is the same defect the
// parser had). Production passes nothing and gets the real tree.
const ROOT = process.env.DEPGATE_ROOT || "libumdnscrypt/src/main";
const files = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (e.name !== "build" && e.name !== ".git") walk(p); }
    else if (e.name.endsWith(".kt")) files.push(p);
  }
})(ROOT);
const byBase = new Map(); const text = new Map();
for (const p of files) { byBase.set(path.basename(p), p); text.set(p, fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n").split("\n")); }

// The call-graph walk lives in callgraph.js -- ONE copy, shared with depclass.js, exercised by
// gated-conformance.js against fixtures. It used to be duplicated here and there, and the two
// copies had ALREADY drifted. The corpus found a real defect in it: the SDK_INT window crossed
// function boundaries and absolved ungated calls. See callgraph.js for the full account.
const { isGated: isGatedRaw } = require(__dirname + "/callgraph.js");
const isGated = (file, line, depth, seen) => isGatedRaw(text, file, line, depth, seen);

// ---- observe -----------------------------------------------------------------------------------
const observed = {};
let unresolved = 0, total = 0, gated = 0;
for (const l of fs.readFileSync(LOG, "utf8").split(/\r?\n/)) {
  // Parsing lives in parse.js -- ONE copy, shared with depclass.js, covered by a conformance
  // corpus (parse-conformance.js) that is mutation-tested. It used to be an inline regex here and
  // an identical inline regex there: two things that can drift, feeding every number this project
  // reports about the backlog. DeprecationKeying.lean proves the COMPARISON is sound; nothing
  // proved the EXTRACTION, and a mis-parse satisfies every theorem while measuring nothing.
  const parsed = parseWarningLine(l);
  if (!parsed) continue;
  total++;
  const base = parsed.base;
  const p = byBase.get(base);
  if (!p) { unresolved++; console.log("  UNRESOLVED PATH: " + base); continue; }
  if (isGated(p, parsed.line, 3, new Set())) { gated++; continue; }
  // The key, from the shared parser -- (basename, symbol), never the line. See
  // Proofs/DeprecationKeying.lean::line_moves_are_invisible for why the line is absent.
  const key = keyOf(parsed);
  observed[key] = (observed[key] || 0) + 1;
}

if (unresolved > 0) { console.log("  FAIL: " + unresolved + " warning(s) could not be resolved to a file."); process.exit(3); }

// ---- THE EMPTY-LOG FLOOR -----------------------------------------------------------------------
// Found by a control that misfired. Simulating a fix by filtering the log accidentally removed ALL
// 34 warnings (gradle separates them with \r, so a line filter took the whole block), and the gate
// reported PASS on zero warnings. That is the worst possible failure mode for a gate: if the
// compile step does not run, or --rerun-tasks is dropped so Kotlin is UP-TO-DATE, or unmute2 fails
// to strip the suppressions, the log has no warnings and a naive gate calls it clean. Green because
// nothing was measured.
//
// A floor, not an exact count: the repo demonstrably contains suppressed deprecations, so a log
// with none of them did not come from a real, stripped compile. This is deliberately NOT a check
// that the count equals the baseline -- fixing everything is a correct future and must stay
// reachable -- but it does require the measurement to have HAPPENED.
// DEPGATE_FLOOR is lowered ONLY by gated-conformance.js, which deliberately feeds one warning at
// a time so each fixture's verdict is attributable. Production never sets it, so the floor that
// protects a real run is the committed 5.
const FLOOR = process.env.DEPGATE_FLOOR !== undefined ? Number(process.env.DEPGATE_FLOOR) : 5;
if (MODE === "check" && total < FLOOR) {
  console.log("  FAIL: only " + total + " deprecation warning(s) in the log (floor " + FLOOR + ").");
  console.log("        This is a BROKEN MEASUREMENT, not a clean tree. Check that the compile");
  console.log("        actually ran with --rerun-tasks and that unmute2.js strip was applied.");
  process.exit(5);
}

if (MODE === "write") {
  fs.writeFileSync(BASE, JSON.stringify(observed, Object.keys(observed).sort(), 2) + "\n", "utf8");
  console.log("  baseline written: " + Object.keys(observed).length + " keys, " +
    Object.values(observed).reduce((a, b) => a + b, 0) + " ungated usages");
  process.exit(0);
}

if (!fs.existsSync(BASE)) { console.log("  FAIL: no baseline at " + BASE + " (run: depgate.js write <log>)"); process.exit(4); }
const baseline = JSON.parse(fs.readFileSync(BASE, "utf8"));

const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
const regressions = [], slack = [];
for (const [k, n] of Object.entries(observed)) {
  const allowed = baseline[k] || 0;
  if (n > allowed) regressions.push(`${k}  observed ${n} > allowed ${allowed}` + (allowed === 0 ? "   (NEW)" : ""));
}
for (const [k, n] of Object.entries(baseline)) {
  const now = observed[k] || 0;
  if (now < n) slack.push(`${k}  ${n} -> ${now}`);
}

console.log("  total=" + total + "  gated=" + gated + "  ungated=" + sum(observed) + "  (baseline allows " + sum(baseline) + ")");
if (slack.length) {
  console.log("  IMPROVED since the baseline -- lower it with `depgate.js write`:");
  for (const s of slack) console.log("     " + s);
}
if (regressions.length) {
  console.log("  FAIL: new ungated deprecated usage. Either gate it behind a version check,");
  console.log("        or fix it. Do NOT widen the baseline to make this pass.");
  for (const r of regressions) console.log("     " + r);
  process.exit(1);
}
console.log("  PASS: no new ungated deprecated usage.");
process.exit(0);
