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
const BASE = "tools/deprecation/deprecation-baseline.json";

if (!LOG || !fs.existsSync(LOG)) { console.log("usage: depgate.js <check|write> <compile-log>"); process.exit(2); }

// ---- reuse depclass's classification -----------------------------------------------------------
const ROOT = "libumdnscrypt/src/main";
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

const FUN = /^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public |private |internal |protected )?(?:override |suspend |inline |open |abstract )*fun\s+(?:<[^>]+>\s*)?([A-Za-z_][A-Za-z0-9_]*)/;
const SDK = /Build\.VERSION\.SDK_INT\s*(?:>=|>|<|<=)/;
const indentOf = (s) => (s.match(/^\s*/) || [""])[0].length;
function enclosingFun(src, line) {
  const want = indentOf(src[line - 1] || "");
  for (let i = line - 1; i >= 0; i--) { const m = src[i] && src[i].match(FUN); if (m && indentOf(src[i]) < want) return { name: m[1] }; }
  return null;
}
const gatedAt = (src, line, win = 15) => SDK.test(src.slice(Math.max(0, line - 1 - win), line).join("\n"));
function callSites(name) {
  const re = new RegExp("(?:^|[^A-Za-z0-9_.])" + name + "\\s*\\(");
  const out = [];
  for (const [p, src] of text) for (let i = 0; i < src.length; i++) { if (re.test(src[i]) && !FUN.test(src[i])) out.push({ file: p, line: i + 1 }); }
  return out;
}
function isGated(file, line, depth, seen) {
  const src = text.get(file); if (!src) return false;
  if (gatedAt(src, line)) return true;
  if (depth <= 0) return false;
  const fn = enclosingFun(src, line); if (!fn) return false;
  const key = file + "#" + fn.name; if (seen.has(key)) return false; seen.add(key);
  const sites = callSites(fn.name); if (sites.length === 0) return false;
  return sites.every((s) => isGated(s.file, s.line, depth - 1, seen));
}

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
const FLOOR = 5;
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
