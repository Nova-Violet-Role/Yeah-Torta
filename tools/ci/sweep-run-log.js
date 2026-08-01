// Sweep a downloaded CI run-log directory for warnings and errors.
//
// WHY THIS IS A FILE AND NOT A SHELL ONE-LINER. The one-liner I had been using was
//
//     T=0; for f in *.txt; do ... done; echo "TOTAL: $T"
//
// and on 2026-08-01 it printed "TOTAL: 0" having examined ZERO files: the run was still in
// progress, so the downloaded "zip" was actually an error page, unzip produced nothing, and an
// unmatched glob in sh iterates the literal string `*.txt`. Every grep failed, every count was 0,
// and the summary read exactly like a perfectly clean run.
//
// That is the same false-green shape as reading an exit code through a pipe, and it appeared in the
// very instrument I use to CHECK for false greens. So the rule this file enforces:
//
//     a sweep that examined nothing must FAIL, never report clean.
//
// It requires a minimum job count, requires every file to be non-trivial, and exits non-zero when
// the input does not look like a real run log.
const fs = require("fs");
const path = require("path");

const DIR = process.argv[2];
const MIN_JOBS = Number(process.argv[3] || 3);

if (!DIR || !fs.existsSync(DIR)) { console.log("  FAIL: no such directory: " + DIR); process.exit(2); }

const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".txt"));
if (files.length < MIN_JOBS) {
  console.log("  FAIL: found " + files.length + " job log(s), expected at least " + MIN_JOBS + ".");
  console.log("        A sweep that examined nothing is a BROKEN MEASUREMENT, not a clean run.");
  console.log("        (Most likely the run had not completed when the log zip was fetched.)");
  process.exit(3);
}

const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "").replace(/^[0-9T:.Z-]*Z /gm, "");
let total = 0, tiny = 0;
const rows = [];
for (const f of files.sort()) {
  const raw = fs.readFileSync(path.join(DIR, f), "utf8");
  if (raw.length < 200) tiny++;
  const c = strip(raw).split(/\r?\n/);
  const rust = c.filter((l) => /^warning: /.test(l)).length;
  const kotlin = c.filter((l) => /^w: file/.test(l)).length;
  const err = c.filter((l) => /^##\[error\]/.test(l)).length;
  total += rust + kotlin + err;
  rows.push({ f, rust, kotlin, err, bytes: raw.length });
}

for (const r of rows) {
  console.log("  " + r.f.padEnd(42) + " rust=" + r.rust + " kotlin=" + r.kotlin + " err=" + r.err + "  (" + r.bytes + "B)");
}
if (tiny > 0) {
  console.log("  FAIL: " + tiny + " job log(s) under 200 bytes -- truncated or empty, so the sweep proves nothing.");
  process.exit(4);
}
console.log("  jobs swept: " + rows.length + "   TOTAL warnings+errors: " + total);
process.exit(total === 0 ? 0 : 1);
