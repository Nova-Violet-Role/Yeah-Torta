// Conformance corpus for tools/deprecation/parse.js -- the front door of every deprecation number.
//
// Proofs/DeprecationKeying.lean proves the ceiling gate compares keys correctly and is invariant
// under line moves. That is a theorem about the COMPARISON. It says nothing about the EXTRACTION
// that produces the keys, and a mis-parse would satisfy every one of those theorems while
// measuring nothing -- the model would be perfect and its inputs fictional.
//
// This is the binding: real compiler output in, expected (base, symbol) out, executed through the
// REAL parser rather than a re-implementation of it. Cases marked MEASURED were copied verbatim
// out of a live `compileArm64DebugKotlin` log; the adversarial ones probe the branches that log
// does not currently exercise, which is exactly where an untested fallback hides.
"use strict";
const { parseWarningLine, keyOf } = require("./parse.js");

// [description, input line, expected key or null]
const CASES = [
  // ---- MEASURED: verbatim from a real compile log ------------------------------------------
  ["MEASURED plain class",
   "w: file:///C:/GIT%20External%20Repo/Yeah!Tort%C3%A4-Universal-x86_64/libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/modules/ModulesReceiver.kt:999:34 'class NetworkInfo : Any, Parcelable' is deprecated. Deprecated in Java",
   "ModulesReceiver.kt|NetworkInfo"],

  ["MEASURED static field",
   "w: file:///C:/GIT%20External%20Repo/Yeah!Tort%C3%A4-Universal-x86_64/libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/modules/ModulesReceiver.kt:1329:60 'static field CONNECTIVITY_ACTION: String' is deprecated. Deprecated in Java",
   "ModulesReceiver.kt|CONNECTIVITY_ACTION"],

  ["MEASURED val with type",
   "w: file:///C:/GIT%20External%20Repo/Yeah!Tort%C3%A4-Universal-x86_64/libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/dns_engine/SolverCacheManager.kt:240:37 'val allNetworks: Array<(out) Network!>' is deprecated. Deprecated in Java",
   "SolverCacheManager.kt|allNetworks"],

  ["MEASURED fun with params",
   "w: file:///C:/GIT%20External%20Repo/Yeah!Tort%C3%A4-Universal-x86_64/libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/utils/ap/ApManager.kt:67:37 'fun setWifiEnabled(p0: Boolean): Boolean' is deprecated. Deprecated in Java",
   "ApManager.kt|setWifiEnabled"],

  ["MEASURED var property",
   "w: file:///C:/GIT%20External%20Repo/Yeah!Tort%C3%A4-Universal-x86_64/libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/dialogs/ExtendedDialogFragment.kt:45:9 'var retainInstance: Boolean' is deprecated. Deprecated in Java",
   "ExtendedDialogFragment.kt|retainInstance"],

  // ---- THE NON-ASCII PATH: this repo's own directory name -----------------------------------
  // Tort%C3%A4 must decode to Tortä. A parser that skips decodeURIComponent still produces the
  // right BASENAME here (the non-ASCII part is a parent directory), which is precisely why this
  // needs an explicit case: it would pass by accident and then fail on a non-ASCII FILE name.
  ["non-ASCII in the FILE name, not just a parent",
   "w: file:///C:/repo/Fi%C3%A4le.kt:10:5 'class Foo' is deprecated.",
   "Fiäle.kt|Foo"],

  // ---- ADVERSARIAL: branches the live log does not currently reach ---------------------------
  ["no quoted declaration -> 40-char fallback, NOT a dropped line",
   "w: file:///C:/repo/Weird.kt:7:1 something deprecated without any quotes at all here",
   "Weird.kt|something deprecated without any quotes"],

  ["generic type in the symbol is cut at the colon",
   "w: file:///C:/repo/Gen.kt:3:3 'fun <T : Parcelable!> getParcelableExtra(p0: String!): T!' is deprecated.",
   "Gen.kt|<T"],

  ["not a warning line at all",
   "> Task :libumdnscrypt:compileArm64DebugKotlin",
   null],

  ["an ERROR line must not be counted as a deprecation",
   "e: file:///C:/repo/Broken.kt:1:1 unresolved reference",
   null],

  ["a .java warning is out of scope (the gate is Kotlin-only)",
   "w: file:///C:/repo/Legacy.java:5:5 'class NetworkInfo' is deprecated.",
   null],

  ["trailing CR (gradle separates warning blocks with \\r) does not corrupt the symbol",
   "w: file:///C:/repo/Crlf.kt:9:9 'class NetworkInfo : Any' is deprecated.\r",
   "Crlf.kt|NetworkInfo"],
];

let pass = 0, fail = 0;
for (const [desc, input, expected] of CASES) {
  const p = parseWarningLine(input.replace(/\r$/, ""));
  const got = p ? keyOf(p) : null;
  if (got === expected) { pass++; }
  else {
    fail++;
    console.log("  FAIL: " + desc);
    console.log("        expected: " + JSON.stringify(expected));
    console.log("        got:      " + JSON.stringify(got));
  }
}

// A corpus that shrank to nothing would report a perfect score. Same defect as an empty-log gate.
const FLOOR = 10;
if (CASES.length < FLOOR) {
  console.log("  FAIL: corpus has only " + CASES.length + " cases, floor is " + FLOOR +
              " -- a suite that examined almost nothing must not report success.");
  process.exit(3);
}

console.log("  parse conformance: " + pass + "/" + CASES.length + " passed, " + fail + " failed");
process.exit(fail === 0 ? 0 : 1);
