// Conformance corpus for unmute2.js's suppression stripper -- the ROOT of the measurement chain.
//
// Everything downstream is measured on whatever this tool leaves behind. If it under-strips, the
// compiler reports fewer warnings, the classifier classifies fewer, the ceiling gate compares
// fewer, and all five CI gates stay green on a number that is simply wrong. There is no floor,
// theorem or corpus further down that can detect it: depgate's FLOOR checks that SOME warnings
// arrived, not that ALL of them did.
//
// That is not hypothetical. Measured 2026-08-01: the tool matched the exact literal
// `@Suppress("DEPRECATION")`, Kotlin's suppression names are case-insensitive, and six
// `@Suppress("deprecation")` in the tree masked FORTY-FIVE deprecations. 34 reported, 79 real.
//
// The cases below therefore include every spelling Kotlin accepts, not merely the ones present
// today -- a corpus built from today's tree would have passed the broken version.
"use strict";
const { stripDeprecationSuppressions, MARK } = require("./unmute2.js");

// [description, input, expected output, expected removal count]
const CASES = [
  ["canonical uppercase",
   'class A {\n    @Suppress("DEPRECATION")\n    fun f() {}\n}',
   'class A {\n    ' + MARK + '\n    fun f() {}\n}', 1],

  ["lowercase -- the spelling that hid 45 warnings",
   '@Suppress("deprecation")\nobject NetworkChecker {}',
   MARK + '\nobject NetworkChecker {}', 1],

  ["mixed case",
   '@Suppress("Deprecation")\nfun f() {}',
   MARK + '\nfun f() {}', 1],

  ["file-level suppression mutes a WHOLE file and must not be missed",
   '@file:Suppress("DEPRECATION")\npackage x',
   MARK + '\npackage x', 1],

  ["whitespace inside the parentheses",
   '@Suppress(  "DEPRECATION"  )\nfun f() {}',
   MARK + '\nfun f() {}', 1],

  ["space between the name and the parenthesis",
   '@Suppress ("DEPRECATION")\nfun f() {}',
   MARK + '\nfun f() {}', 1],

  ["multi-arg: keep the others, drop only deprecation",
   '@Suppress("DEPRECATION", "UNCHECKED_CAST")\nfun f() {}',
   '@Suppress("UNCHECKED_CAST")\nfun f() {}', 1],

  ["multi-arg, deprecation second",
   '@Suppress("UNCHECKED_CAST", "deprecation")\nfun f() {}',
   '@Suppress("UNCHECKED_CAST")\nfun f() {}', 1],

  ["multi-arg with three, two survivors",
   '@Suppress("A", "DEPRECATION", "B")\nfun f() {}',
   '@Suppress("A", "B")\nfun f() {}', 1],

  ["an unrelated suppression is left completely alone",
   '@Suppress("UNCHECKED_CAST")\nfun f() {}',
   '@Suppress("UNCHECKED_CAST")\nfun f() {}', 0],

  ["DEPRECATION_ERROR is a DIFFERENT diagnostic and must NOT be stripped",
   '@Suppress("DEPRECATION_ERROR")\nfun f() {}',
   '@Suppress("DEPRECATION_ERROR")\nfun f() {}', 0],

  ["several in one file are all removed",
   '@Suppress("DEPRECATION")\nfun a() {}\n@Suppress("deprecation")\nfun b() {}',
   MARK + '\nfun a() {}\n' + MARK + '\nfun b() {}', 2],

  ["a file with none is untouched",
   'package x\nfun f() {}',
   'package x\nfun f() {}', 0],
];

const FLOOR = 12;
if (CASES.length < FLOOR) {
  console.log("  FAIL: " + CASES.length + " cases, floor " + FLOOR);
  process.exit(3);
}

let pass = 0, fail = 0;
for (const [desc, input, expected, expectedRemoved] of CASES) {
  const { out, removed } = stripDeprecationSuppressions(input);
  if (out === expected && removed === expectedRemoved) { pass++; console.log("  ok   " + desc); }
  else {
    fail++;
    console.log("  FAIL " + desc);
    if (out !== expected) {
      console.log("       expected: " + JSON.stringify(expected));
      console.log("       got:      " + JSON.stringify(out));
    }
    if (removed !== expectedRemoved) {
      console.log("       expected removed=" + expectedRemoved + ", got " + removed);
    }
  }
}

console.log("  unmute conformance: " + pass + "/" + CASES.length + " passed, " + fail + " failed");
process.exit(fail === 0 ? 0 : 1);
