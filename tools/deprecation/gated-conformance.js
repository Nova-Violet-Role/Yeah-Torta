// Conformance corpus for the isGated CALL-GRAPH WALK in depgate.js.
//
// isGated decides 57 of the 79 measured warnings: whether a deprecated call is a legacy branch
// REQUIRED by minSdk 21, or a real backlog item that runs on every device. It was the last
// component with neither a corpus nor a theorem. A bug in it moves usages between GATED and
// UNGATED silently -- the total is still 79 either way, so nothing looks wrong.
//
// (The counts here said "15 of 34" until unmute2.js was fixed on 2026-08-01; it had been
// case-sensitive, six lowercase @Suppress("deprecation") were masking 45 warnings, and every
// figure downstream was low. A comment stating a measured number goes stale the moment the
// measurement improves, which is why the number is restated rather than left to rot.)
//
// This runs the REAL depgate.js against fixture sources (via DEPGATE_ROOT) and a synthetic
// compile log, then asserts the verdict for each fixture. It does not re-implement the walk:
// two copies of a classifier is precisely the defect the parser had.
//
// THE CONTRACT UNDER TEST, which is a SAFETY property and not a precision one: every branch of
// isGated that means "I do not know" returns false, i.e. UNGATED.
//   unknown file      -> false      depth exhausted -> false
//   no enclosing fun  -> false      cycle detected  -> false
//   no call sites     -> false      any caller ungated -> false  (sites.every)
// Precision is allowed to be poor. Absolving something that is not gated is not.
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const FIX = "tools/deprecation/fixtures/kt";

// [fixture file, 1-based line of the legacyCall(), expected verdict, why]
const CASES = [
  ["DirectGate.kt", 9, "gated",
   "the call sits in the else of an SDK_INT test, directly above"],
  ["FarEnclosingGate.kt", 27, "gated",
   "ENCLOSED by an SDK_INT test 20 lines up -- distance is not the question (NetworkChecker:159)"],
  ["AfterGateCloses.kt", 14, "ungated",
   "the SDK_INT block CLOSED before this call; a closed block is never an enclosing opener"],
  ["NestedGate.kt", 11, "gated",
   "SDK_INT is on an OUTER block with an unrelated if between -- keep walking outward, do not stop"],
  ["CallerGate.kt", 7, "gated",
   "no local gate; its ONLY call site is inside an SDK_INT branch"],
  ["MixedCallers.kt", 8, "ungated",
   "two callers, one ungated -- sites.every must reject (the ModulesReceiver try/catch shape)"],
  ["NoCallers.kt", 7, "ungated",
   "no discoverable call site; unknown is never absolved"],
  ["TopLevelProperty.kt", 8, "ungated",
   "property initialiser -- no enclosing function, runs at class-init on every device"],
  ["Cycle.kt", 7, "ungated",
   "mutual recursion; the seen-set must break the cycle to false, not loop or absolve"],
  ["DeepChain.kt", 8, "ungated",
   "gate is 4 levels up, walk is bounded at 3 -- an unfinished search is not evidence of safety"],
  ["AnonObject.kt", 16, "gated",
   "enclosing fun found by INDENT, not by nearest-above (an anon object's override sits between)"],
];

const FLOOR = 11;
if (CASES.length < FLOOR) {
  console.log("  FAIL: " + CASES.length + " cases, floor " + FLOOR + " -- a corpus that examined" +
              " almost nothing must not report success.");
  process.exit(3);
}

// Build a synthetic compile log in the exact shape Kotlin emits, one warning per case.
const abs = (f) => path.resolve(FIX, f).replace(/\\/g, "/");
const logLines = CASES.map(([f, line]) =>
  "w: file:///" + encodeURI(abs(f)) + ":" + line + ":9 'fun legacyCall(): String' is deprecated. Deprecated in Java");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "gatedconf-"));
const logPath = path.join(tmp, "fixture.log");
fs.writeFileSync(logPath, logLines.join("\n") + "\n", { encoding: "utf8" });

// A baseline that allows nothing, so every UNGATED case shows up by name in the failure report.
const basePath = path.join(tmp, "baseline.json");
fs.writeFileSync(basePath, JSON.stringify({}), "utf8");

function runOne(idx) {
  // One warning at a time: depgate reports aggregate counts, and per-case attribution is what
  // makes a failure actionable rather than "one of six moved".
  const one = path.join(tmp, "one" + idx + ".log");
  fs.writeFileSync(one, logLines[idx] + "\n", "utf8");
  let out;
  try {
    out = execFileSync(process.execPath, ["tools/deprecation/depgate.js", "check", one], {
      encoding: "utf8",
      env: Object.assign({}, process.env, { DEPGATE_ROOT: FIX, DEPGATE_BASELINE: basePath, DEPGATE_FLOOR: "0" }),
    });
  } catch (e) { out = (e.stdout || "") + (e.stderr || ""); }
  const m = out.match(/total=(\d+)\s+gated=(\d+)\s+ungated=(\d+)/);
  if (!m) return { verdict: "UNPARSEABLE", out };
  if (m[1] !== "1") return { verdict: "NOT-SEEN(total=" + m[1] + ")", out };
  return { verdict: m[2] === "1" ? "gated" : "ungated", out };
}

let pass = 0, fail = 0;
for (let i = 0; i < CASES.length; i++) {
  const [f, line, expected, why] = CASES[i];
  const r = runOne(i);
  if (r.verdict === expected) { pass++; console.log("  ok   " + f.padEnd(22) + expected.padEnd(8) + why); }
  else {
    fail++;
    console.log("  FAIL " + f.padEnd(22) + "expected " + expected + ", got " + r.verdict);
    console.log("       " + why);
    console.log(r.out.split("\n").slice(0, 6).map((l) => "       | " + l).join("\n"));
  }
}

fs.rmSync(tmp, { recursive: true, force: true });

// ---- DIRECT API ASSERTIONS ---------------------------------------------------------------------
// Two branches of isGated cannot be reached through depgate.js at all: it only ever calls isGated
// with a path taken from its own on-disk index, so `text.get(file)` always resolves, and it always
// starts at depth 3. A mutation that made either branch ABSOLVE therefore survived the fixture
// corpus -- not because the corpus was weak, but because those paths are unreachable from it.
//
// They are not dead code: they are the module's contract for any caller. So they are tested at the
// module's own API, which is the honest place for them. Deleting them instead would remove the
// guarantee that a future caller passing an unknown file gets a SAFE answer.
const cg = require("./callgraph.js");
const emptyText = new Map();
const API = [
  ["unknown file must not be absolved",
   () => cg.isGated(emptyText, "NoSuchFile.kt", 1, 3, new Set()) === false],
  ["depth 0 must not be absolved",
   () => cg.isGated(new Map([["f.kt", ["fun a() {", "  legacyCall()", "}"]]]), "f.kt", 2, 0, new Set()) === false],
  ["a gate INSIDE the same function is still found at depth 0",
   () => cg.gatedAt(["fun a() {", "  if (Build.VERSION.SDK_INT >= 23) {", "    legacyCall()"], 3) === true],
  ["a gate in the PREVIOUS function is not borrowed",
   () => cg.gatedAt(["fun a() {", "  if (Build.VERSION.SDK_INT >= 23) { x() }", "}", "fun b() {", "  legacyCall()"], 5) === false],
  // A single-line guard has no enclosing block at all -- the test and the call share one line.
  // A mutation that stopped checking the call's own line survived until this assertion existed.
  ["a SINGLE-LINE guard counts: if (SDK_INT >= 23) legacyCall()",
   () => cg.gatedAt(["fun a() {", "  if (Build.VERSION.SDK_INT >= 23) legacyCall()"], 2) === true],
  ["and a single-line call with NO guard does not",
   () => cg.gatedAt(["fun a() {", "  legacyCall()"], 2) === false],
];
for (const [desc, fn] of API) {
  let ok = false;
  try { ok = fn(); } catch (e) { console.log("  FAIL " + desc + " -- threw " + e.message); }
  if (ok) { pass++; console.log("  ok   " + "<api>".padEnd(22) + desc); }
  else { fail++; console.log("  FAIL " + "<api>".padEnd(22) + desc); }
}

const TOTAL = CASES.length + API.length;
console.log("  isGated conformance: " + pass + "/" + TOTAL + " passed, " + fail + " failed");
process.exit(fail === 0 ? 0 : 1);
