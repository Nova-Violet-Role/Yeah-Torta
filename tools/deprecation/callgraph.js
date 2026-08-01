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
 * Is `line` within `win` lines below an SDK_INT test **in the same function**?
 *
 * The clamp at the enclosing declaration is the fix described at the top of this file. Without it
 * the scan reaches into the previous function and absolves an ungated call.
 */
function gatedAt(src, line, win = 15) {
  const fn = enclosingFun(src, line);
  // Never look above the enclosing declaration. When there is no enclosing function at all (a
  // property initialiser, say) the window is unrestricted-but-textual as before -- such a site has
  // no caller to be gated by, and is reported UNGATED by the walk regardless.
  const floor = fn ? fn.at : 0;
  const start = Math.max(0, line - 1 - win, floor);
  return SDK.test(src.slice(start, line).join("\n"));
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
