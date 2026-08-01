#!/usr/bin/env node
/*
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2

    Yeah! Tortä
    Copyright 2026 Saimonokuma

    README NUMBER SYNC -- measure the tree, then rewrite the numbers README.md advertises.

    WHY THIS EXISTS. The Ads Manager workflow already fails the build when README.md claims a
    subsystem line count the tree does not have. That gate is correct and it caught a real drift
    (mirror 24,222 -> 24,407, warden 9,751 -> 10,087, beast 7,785 -> 8,364, forwarder 3,603 ->
    3,686). But a gate that can only say NO turns every code change into a manual arithmetic
    chore, and the predictable outcome of that is somebody "fixing" the gate instead of the
    number. So the same measurement now has a writer as well as a checker.

    THE RULE THIS ENFORCES: the README's numbers and the gate's numbers come from ONE function,
    `measure()`. There is no second definition to drift from the first. `--check` is what CI runs;
    with no flag it rewrites README.md in place.

    IT ALSO COVERS WHAT THE GATE MISSED. The workflow measured `tests`, `files`, `rs`, `kt` and
    `slint` and then compared only the four subsystem counts, throwing the rest away. Meanwhile the
    test badge said 1311 while the tree had 1370, and the headline said 2,437 files / 615,494 lines
    while the tree had 2,691 / 643,973. Numbers nobody checks are numbers that are wrong.

    THE TOTAL IS SELF-REFERENTIAL, and that is stated rather than discovered. `totalLines` counts
    every tracked file, which includes the workflow that runs this check and this file itself. Add
    a line anywhere and the total moves. It was found the honest way: the negative control below
    failed on a README that had just passed, because editing ads-manager.yml added 14 lines
    (160 -> 174) and pushed the total from 643,973 to 643,987.

    A fixed point still exists and is easy to reach, because rewriting a DIGIT does not change a
    line COUNT -- so the ritual is: make every other edit first, run this tool LAST, then commit.
    If a future change ever makes a claim that alters its own line count, this converges no longer
    and the claim must be dropped rather than iterated.
*/

"use strict";

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = process.env.README_ROOT || path.resolve(__dirname, "..", "..");
const README = process.env.README_FILE || path.join(ROOT, "README.md");
const VENDORED = "uniffi-rs-main/";

function git(args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 28 });
}

/** Tracked files matching a pathspec, as a list. Untracked build output must never count. */
function tracked(spec) {
  const out = spec ? git(["ls-files", spec]) : git(["ls-files"]);
  return out.split("\n").filter((l) => l.length > 0);
}

/**
 * Line count of a list of files, counted the way `cat ... | wc -l` counts: by newline.
 * A final line with no trailing newline is therefore not counted, which is exactly what the
 * shell pipeline in the workflow does -- the two must agree or the gate is comparing two
 * different quantities.
 */
function lines(files) {
  let n = 0;
  for (const f of files) {
    const p = path.join(ROOT, f);
    let buf;
    try {
      buf = fs.readFileSync(p);
    } catch {
      continue; // a tracked file missing from the working tree: skip, do not crash the gate
    }
    for (let i = 0; i < buf.length; i++) if (buf[i] === 0x0a) n++;
  }
  return n;
}

function dirLines(rel) {
  const dir = path.join(ROOT, rel);
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".rs"))
    .map((f) => path.join(rel, f));
  return lines(files);
}

/** Every number README.md is allowed to state about the size of this tree. */
function measure() {
  const all = tracked(null);
  const rs = tracked("*.rs");
  const kt = tracked("*.kt");
  const slint = tracked("*.slint");
  const notVendored = (f) => !f.startsWith(VENDORED);

  const projRs = rs.filter(notVendored);
  const projKt = kt.filter(notVendored);
  const projSlint = slint.filter(notVendored);

  const testAttrs = rs
    .filter((f) => f.startsWith("rust/torta_core/src/"))
    .reduce((acc, f) => {
      const t = fs.readFileSync(path.join(ROOT, f), "utf8");
      return acc + (t.split("#[test]").length - 1);
    }, 0);

  return {
    tests: testAttrs,
    files: all.length,
    totalLines: lines(all),
    vendoredFiles: all.filter((f) => f.startsWith(VENDORED)).length,
    mirror: dirLines("rust/torta_core/src/mirror"),
    warden: dirLines("rust/torta_core/src/warden"),
    beast: dirLines("rust/torta_core/src/beast"),
    forwarder: dirLines("rust/torta_core/src/forwarder"),
    libRs: lines(["rust/torta_core/src/lib.rs"]),
    projRsFiles: projRs.length,
    projRsLines: lines(projRs),
    projKtFiles: projKt.length,
    projKtLines: lines(projKt),
    projSlintFiles: projSlint.length,
    projSlintLines: lines(projSlint)
  };
}

const grp = (n) => n.toLocaleString("en-US");

/**
 * Every claim in README.md, as a (regex, replacement) pair.
 *
 * Each regex captures the surrounding text so the rewrite cannot damage prose, and each is
 * asserted to match EXACTLY ONCE. A pattern that matches zero times is a silent no-op -- the
 * failure mode where a sync tool reports success having changed nothing.
 */
function claims(m) {
  return [
    ["tests badge", /(engine%20tests-)(\d+)(%20passing)/, `$1${m.tests}$3`],
    ["warden lines", /(`rust\/torta_core\/src\/warden\/` · )([\d,]+)( lines)/, `$1${grp(m.warden)}$3`],
    ["mirror lines", /(`rust\/torta_core\/src\/mirror\/` · )([\d,]+)( lines)/, `$1${grp(m.mirror)}$3`],
    ["beast lines", /(`rust\/torta_core\/src\/beast\/` · )([\d,]+)( lines)/, `$1${grp(m.beast)}$3`],
    ["forwarder lines", /(`rust\/torta_core\/src\/forwarder\/` · )([\d,]+)( lines)/, `$1${grp(m.forwarder)}$3`],
    ["lib.rs lines", /(\*\*sliced\*\*: )([\d,]+)( lines)/, `$1${grp(m.libRs)}$3`],
    [
      "tree totals",
      /(on the published tree, \*\*)([\d,]+)( files \/ )([\d,]+)( lines\*\*)/,
      `$1${grp(m.files)}$3${grp(m.totalLines)}$5`
    ],
    [
      "vendored file count",
      /(subtree \()([\d,]+)( files\))/,
      `$1${grp(m.vendoredFiles)}$3`
    ],
    [
      "project rs",
      /(is:\*\* )([\d,]+)( `\.rs` files \/ )([\d,]+)( lines)/,
      `$1${grp(m.projRsFiles)}$3${grp(m.projRsLines)}$5`
    ],
    [
      "project kt",
      /(, )([\d,]+)( `\.kt` \/ )([\d,]+)( lines)/,
      `$1${grp(m.projKtFiles)}$3${grp(m.projKtLines)}$5`
    ],
    [
      "project slint",
      /(, )([\d,]+)( `\.slint` \/ )([\d,]+)( lines)/,
      `$1${grp(m.projSlintFiles)}$3${grp(m.projSlintLines)}$5`
    ]
  ];
}

function main() {
  const mode = process.argv[2] || "";
  const m = measure();
  const src = fs.readFileSync(README, "utf8");
  let out = src;
  let drift = 0;
  let missing = 0;

  for (const [label, re, repl] of claims(m)) {
    const g = new RegExp(re.source, "g");
    const hits = (out.match(g) || []).length;
    if (hits !== 1) {
      console.log(`  MISSING  ${label}: pattern matched ${hits} times, expected exactly 1`);
      missing++;
      continue;
    }
    const next = out.replace(re, repl);
    if (next !== out) {
      const before = (out.match(re) || []).slice(1).filter((x) => /^[\d,%]/.test(x)).join(" / ");
      const after = (next.match(re) || []).slice(1).filter((x) => /^[\d,%]/.test(x)).join(" / ");
      console.log(`  DRIFT    ${label}: README said ${before || "?"}, tree measures ${after || "?"}`);
      drift++;
      out = next;
    } else {
      console.log(`  ok       ${label}`);
    }
  }

  if (missing > 0) {
    console.log(`FAIL: ${missing} claim pattern(s) did not match exactly once.`);
    console.log("A pattern that matches nothing cannot detect drift -- fix the pattern, not the README.");
    process.exit(4);
  }

  if (mode === "--check") {
    if (drift > 0) {
      console.log(`FAIL: ${drift} README number(s) do not match the tree.`);
      console.log("Run: node tools/readme/sync-readme-numbers.js   (then commit README.md)");
      process.exit(1);
    }
    console.log("PASS: every number README.md states matches the tree.");
    return;
  }

  if (drift > 0) {
    fs.writeFileSync(README, out, { encoding: "utf8" });
    console.log(`README.md updated: ${drift} number(s) re-measured.`);
  } else {
    console.log("README.md already matches the tree; nothing written.");
  }
}

if (require.main === module) main();
module.exports = { measure, claims };
