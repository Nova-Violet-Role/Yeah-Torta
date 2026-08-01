// The ONE call-graph walk behind the deprecation GATED/UNGATED decision.
// Required by depgate.js (which enforces) and depclass.js (which reports).
//
// ============================================================================================
// A REAL DEFECT LIVED HERE, IN THE UNSAFE DIRECTION. Found 2026-08-01 by the fixture corpus
// (gated-conformance.js), which is the first thing that ever exercised this code.
//
// `gatedAt` asked: is there a `Build.VERSION.SDK_INT` test in the 15 source lines above this
// call? That window was purely textual and CROSSED FUNCTION BOUNDARIES. So:
//
//     fun gatedEntry() {
//         if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
//             mixedHelper()                 // genuinely gated
//         }
//     }
//
//     fun ungatedEntry() {
//         mixedHelper()                     // NOT gated -- but the test above is within 15 lines
//     }
//
// classified the second call as GATED. A sibling function's version test says nothing whatsoever
// about this call, and the effect is to ABSOLVE a usage that runs on every device.
//
// Every other "I do not know" branch of this walk returns UNGATED, deliberately: unknown file,
// depth exhausted, no enclosing function, cycle, no call sites, any caller ungated. Those are all
// safe. This one was the exception, and it was the only branch that could mark something safe
// without evidence -- which makes it the only one whose bug could shrink the backlog silently.
//
// THE FIX: the window is clamped at the enclosing declaration. A gate must be inside the same
// function as the call it guards. Measured effect on the real tree is recorded in the commit.
//
// It is a shared module for the same reason parse.js is: depgate.js and depclass.js each carried
// their own copy, and they had ALREADY drifted -- depclass's enclosingFun returned an `at` field
// depgate's did not, and its gatedAt doc claimed "inside the same file" while doing the same
// unclamped scan. Two copies of a classifier is two verdicts waiting to disagree.
// ============================================================================================
"use strict";

/** A Kotlin function declaration, with optional annotations/modifiers. Capture 1 is the name. */
const FUN =
  /^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public |private |internal |protected )?(?:override |suspend |inline |operator |tailrec )*fun\s+(?:<[^>]*>\s*)?(\w+)\s*\(/;

/** Any Build.VERSION.SDK_INT comparison. */
const SDK = /Build\.VERSION\.SDK_INT\s*(?:>=|>|<|<=)/;

const indentOf = (s) => (s.match(/^\s*/) || [""])[0].length;

/**
 * The function declaration that CONTAINS `line` (1-based).
 *
 * The indentation test is load-bearing: without it a naive upward scan returns an `override fun`
 * declared INSIDE an anonymous object below the statement -- nested deeper, textually above --
 * whose call sites are the framework's and therefore invisible. Requiring the declaration to be
 * less indented than the statement selects the member that actually contains it.
 *
 * @returns {{name:string, at:number}|null} `at` is the 1-based line AFTER the declaration.
 */
function enclosingFun(src, line) {
  const want = indentOf(src[line - 1] || "");
  for (let i = line - 1; i >= 0; i--) {
    const m = src[i] && src[i].match(FUN);
    if (m && indentOf(src[i]) < want) return { name: m[1], at: i + 1 };
  }
  return null;
}

/**
 * Is `line` inside a block whose condition tests `SDK_INT`?
 *
 * ============================================================================================
 * DISTANCE WAS THE WRONG QUESTION. This used to ask "is there an SDK_INT test in the 15 lines
 * above", which is a proxy for enclosure and wrong in BOTH directions:
 *
 *   FALSE POSITIVE (unsafe): ExtendedDialogFragment.kt:89 was absolved by a test at :79 that
 *     belonged to a function which had already CLOSED at :83. Fixed 2026-08-01 by clamping the
 *     window at the enclosing declaration.
 *
 *   FALSE NEGATIVE (imprecise): NetworkChecker.kt:159 sits in the `else` of an SDK_INT test at
 *     :141 -- unambiguously version-guarded, and eighteen lines up, so the window missed it. Its
 *     identical twin at :153 was counted gated purely because it happened to be nearer.
 *
 * A rule where two identical expressions in the same conditional get opposite verdicts because of
 * line spacing is not measuring what it claims to measure.
 *
 * WHAT IT ASKS NOW. Walk upward tracking brace depth. A line that leaves the running depth
 * negative is a line that OPENED a block still enclosing our call. If any such block header tests
 * SDK_INT, the call is version-guarded, at any distance. If we reach the enclosing function
 * declaration first, it is not.
 *
 * This is sound in both directions: a conditional that has already closed can never be an
 * enclosing opener, so the ExtendedDialogFragment case stays UNGATED; and an enclosing `if` stays
 * found however far above it sits. `} else {` and `} else if (...) {` are net-zero lines, so the
 * scan walks on to the matching `if` that carries the condition -- which is where the SDK_INT test
 * actually lives in a legacy fallback.
 * ============================================================================================
 */
function gatedAt(src, line) {
  const fn = enclosingFun(src, line);
  // INFRASTRUCTURE, not load-bearing -- labelled honestly because a mutation removing it SURVIVED
  // the corpus and I could not construct a case that distinguishes it. Under the brace-depth rule
  // the clamp is redundant: a sibling function's conditional has already closed, so it can never
  // register as an enclosing opener, and the ExtendedDialogFragment case stays UNGATED with or
  // without this line. It is kept as a bound on the damage if brace accounting is ever thrown off
  // (a brace inside a string literal, say) -- cheap insurance, and NOT a guarantee this corpus
  // tests. Calling it load-bearing would be the overclaim.
  const floor = fn ? fn.at - 1 : 0;   // 0-based index of the declaration itself
  // The call's own line counts: `if (SDK_INT >= M) foo()` on one line is gated.
  if (SDK.test(src[line - 1] || "")) return true;
  let depth = 0;
  for (let i = line - 2; i >= floor; i--) {
    const l = src[i] || "";
    const opens = (l.match(/\{/g) || []).length;
    const closes = (l.match(/\}/g) || []).length;
    depth += closes - opens;
    if (depth < 0) {
      // This line opened a block that still encloses `line`.
      if (SDK.test(l)) return true;
      depth = 0;                      // continue outward from this block's header
    }
  }
  return false;
}

/** Every call site of `name` across the indexed module, as {file, line}. */
function callSites(text, name) {
  const re = new RegExp("(?:^|[^A-Za-z0-9_.])" + name + "\\s*\\(");
  const out = [];
  for (const [p, src] of text) {
    for (let i = 0; i < src.length; i++) {
      if (re.test(src[i]) && !FUN.test(src[i])) out.push({ file: p, line: i + 1 });
    }
  }
  return out;
}

/**
 * Is this deprecated usage reachable ONLY on API levels that require it?
 *
 * Every uncertain branch answers false (UNGATED). Precision may be poor; absolving something that
 * is not gated must not happen. Proofs/GateConservatism.lean states that contract as theorems.
 */
function isGated(text, file, line, depth, seen) {
  const src = text.get(file);
  if (!src) return false;                                   // unknown file
  if (gatedAt(src, line)) return true;                      // a real gate, in this function
  if (depth <= 0) return false;                             // depth exhausted
  const fn = enclosingFun(src, line);
  if (!fn) return false;                                    // no enclosing function
  const key = file + "#" + fn.name;
  if (seen.has(key)) return false;                          // cycle
  seen.add(key);
  const sites = callSites(text, fn.name);
  if (sites.length === 0) return false;                     // no discoverable caller
  return sites.every((s) => isGated(text, s.file, s.line, depth - 1, seen));
}

module.exports = { FUN, SDK, indentOf, enclosingFun, gatedAt, callSites, isGated };
