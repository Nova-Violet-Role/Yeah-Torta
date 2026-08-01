#!/usr/bin/env node
/**
 * A14 INSTRUMENT -- bind every `#[derive(uniffi::Record)]` struct in Rust to the `data class`
 * that ships in the generated Kotlin, FIELD FOR FIELD.
 *
 * WHY THIS EXISTS, AND WHY tools/check_uniffi_abi.py DOES NOT COVER IT
 * -------------------------------------------------------------------
 * That checker proves the ABI SYMBOL surface agrees: every `uniffi_*_fn_*` and
 * `uniffi_*_checksum_*` the Kotlin calls is exported by the .so. That is a different failure
 * mode entirely. A record can keep every symbol it ever had and still be WRONG: add a field to
 * a Rust struct, forget to regenerate the bindings, and the symbol set is untouched while the
 * two sides now disagree about the SHAPE of the bytes crossing the FFI boundary.
 *
 * UniFFI does defend itself at load time with checksums -- but that defence fires as a runtime
 * abort on a device, which for the arm64 flavour cannot be booted on this machine at all. This
 * check moves that failure to build time, where it is cheap.
 *
 * WHAT IT CHECKS
 *   for every record R declared `#[derive(..., uniffi::Record)]` in the Rust crate:
 *     - a `data class R` exists in the generated Kotlin, and
 *     - the two have the SAME NUMBER OF FIELDS, and
 *     - the field NAMES agree as a set (a rename with an equal count is still a break)
 *
 * WHAT IT DOES NOT CHECK
 *   Field TYPES, field ORDER, or that the values mean the same thing. Count+name agreement is a
 *   necessary condition, never a sufficient one. A green run here is not "the bindings are
 *   correct"; it is "the bindings are not STALE in the way that is cheap to detect".
 *
 * EXIT CODES: 0 = every record agrees. 1 = at least one mismatch (the alarm). 2 = the checker
 * could not run (inputs missing) -- deliberately DISTINCT from 1, because "did not run" and
 * "found nothing wrong" must never be reported as the same thing.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const REPO = path.resolve(__dirname, "..");
const RUST_DIR = path.join(REPO, "rust", "torta_core", "src");
const KT = path.join(REPO, "libumdnscrypt", "src", "main", "kotlin", "uniffi", "torta_core", "torta_core.kt");

function die(code, msg) {
  console.error(msg);
  process.exit(code);
}

if (!fs.existsSync(RUST_DIR)) die(2, `CHECKER CANNOT RUN: missing ${RUST_DIR}`);
if (!fs.existsSync(KT)) die(2, `CHECKER CANNOT RUN: missing generated Kotlin ${KT}`);

/**
 * STRIP COMMENTS BEFORE PARSING ANYTHING. This is not tidiness, it is the difference between a
 * working instrument and a false alarm generator.
 *
 * MEASURED: the first version of this checker parsed the generated Kotlin without stripping and
 * found 26 data classes in a file that contains 96. UniFFI emits a KDoc block between fields:
 *
 *     data class ForwarderSnapshot (
 *         /／**
 *          * The runtime toggle ([`TunnelController::set_netstack`]) - armed for the NEXT start.
 *          *／
 *         var `armed`: kotlin.Boolean
 *         ,
 *
 * Those comments carry colons, commas, backticks and parentheses -- every token the field and
 * brace matching keys on. The result was 83 reported "stale records" in a tree whose bindings had
 * been regenerated hours earlier. A checker that cries catastrophe is far more likely broken than
 * the codebase it is judging, and reporting that run as an A14 finding would have been a
 * fabricated alarm -- the mirror image of a false green, and just as corrosive.
 */
function stripComments(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  let inStr = null; // '"' or '`' or "'"
  while (i < n) {
    const c = src[i],
      d = src[i + 1];
    if (inStr) {
      out += c;
      if (c === "\\" && inStr !== "`") {
        out += d === undefined ? "" : d;
        i += 2;
        continue;
      }
      if (c === inStr) inStr = null;
      i++;
      continue;
    }
    if (c === '"' || c === "`" || c === "'") {
      inStr = c;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && d === "*") {
      // preserve newlines so line-oriented logic downstream stays aligned
      let j = i + 2;
      while (j < n && !(src[j] === "*" && src[j + 1] === "/")) {
        if (src[j] === "\n") out += "\n";
        j++;
      }
      i = j + 2;
      continue;
    }
    if (c === "/" && d === "/") {
      let j = i + 2;
      while (j < n && src[j] !== "\n") j++;
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// ---------- collect .rs files ----------
function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".rs")) out.push(p);
  }
  return out;
}

// ---------- parse Rust records ----------
// Brace-matched so a nested type in a field cannot end the struct early.
function parseRustRecords(files) {
  const recs = new Map();
  for (const f of files) {
    const src = stripComments(fs.readFileSync(f, "utf8"));
    const re = /#\[derive\([^)]*uniffi::Record[^)]*\)\]/g;
    let m;
    while ((m = re.exec(src))) {
      const after = src.slice(m.index + m[0].length);
      const sm = after.match(/^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)\s*\{/);
      if (!sm) continue; // tuple struct or something else; skip rather than guess
      const name = sm[1];
      const bodyStart = after.indexOf("{", sm.index + sm[0].length - 1);
      let depth = 0,
        end = -1;
      for (let i = bodyStart; i < after.length; i++) {
        if (after[i] === "{") depth++;
        else if (after[i] === "}") {
          depth--;
          if (depth === 0) {
            end = i;
            break;
          }
        }
      }
      if (end < 0) continue;
      const body = after.slice(bodyStart + 1, end);

      // Count fields at brace-depth 0 of the body: `name : Type,`
      const fields = [];
      let d = 0,
        line = "";
      for (const ch of body) {
        if (ch === "{" || ch === "(" || ch === "<" || ch === "[") d++;
        else if (ch === "}" || ch === ")" || ch === ">" || ch === "]") d--;
        if (ch === "\n") {
          line = "";
          continue;
        }
        line += ch;
      }
      // simpler + robust: strip comments and attributes, then match field heads
      const cleaned = body
        .split("\n")
        .map((l) => l.replace(/\/\/.*$/, "").trim())
        .filter((l) => l && !l.startsWith("#[") && !l.startsWith("///") && !l.startsWith("/*") && !l.startsWith("*"))
        .join("\n");
      const fre = /(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:/g;
      let fm;
      while ((fm = fre.exec(cleaned))) fields.push(fm[1]);

      if (fields.length) recs.set(name, { fields, file: path.relative(REPO, f) });
    }
  }
  return recs;
}

// ---------- parse Kotlin data classes ----------
function parseKotlin(src) {
  const out = new Map();
  const re = /data class (\w+)\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    const name = m[1];
    let i = re.lastIndex - 1,
      depth = 0,
      end = -1;
    for (let j = i; j < src.length; j++) {
      if (src[j] === "(") depth++;
      else if (src[j] === ")") {
        depth--;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    if (end < 0) continue;
    const body = src.slice(i + 1, end);
    const fields = [];
    const fre = /(?:^|,)\s*(?:va[lr]\s+)?`?(\w+)`?\s*:/g;
    let fm;
    while ((fm = fre.exec(body))) fields.push(fm[1]);
    if (fields.length) out.set(name, fields);
  }
  return out;
}

const snake = (s) => s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();

const rust = parseRustRecords(walk(RUST_DIR));
const ktSrc = stripComments(fs.readFileSync(KT, "utf8"));
const kt = parseKotlin(ktSrc);

// SELF-CHECK: the parser must find as many data classes as a dumb textual count says exist.
// This is the guard that would have caught the 26-vs-96 failure immediately instead of letting it
// masquerade as 83 stale records. A parser that silently drops most of its input must ABORT (exit
// 2 = could not run), never quietly report the remainder as if it were the whole picture.
const rawClassCount = (fs.readFileSync(KT, "utf8").match(/^data class /gm) || []).length;
if (kt.size < rawClassCount) {
  die(
    2,
    `CHECKER CANNOT RUN: parsed ${kt.size} Kotlin data classes but the file textually declares ${rawClassCount}. ` +
      `The PARSER is wrong, not the bindings -- fix it before trusting any verdict from this tool.`
  );
}

if (rust.size === 0) die(2, "CHECKER CANNOT RUN: parsed 0 uniffi::Record structs -- the parser is broken, not the code");
if (kt.size === 0) die(2, "CHECKER CANNOT RUN: parsed 0 data classes from the generated Kotlin");

const problems = [];
let compared = 0;
for (const [name, info] of rust) {
  const kf = kt.get(name);
  if (!kf) {
    problems.push(`MISSING IN KOTLIN: record ${name} (${info.file}) has no \`data class ${name}\` -- bindings not regenerated`);
    continue;
  }
  compared++;
  if (kf.length !== info.fields.length) {
    problems.push(
      `FIELD COUNT MISMATCH: ${name} -- Rust ${info.fields.length} vs Kotlin ${kf.length} (${info.file}). Regenerate the UniFFI bindings.`
    );
    continue;
  }
  const a = new Set(info.fields.map(snake));
  const b = new Set(kf.map(snake));
  const missing = [...a].filter((x) => !b.has(x));
  const extra = [...b].filter((x) => !a.has(x));
  if (missing.length || extra.length) {
    problems.push(
      `FIELD NAME MISMATCH: ${name} -- only in Rust: [${missing}] ; only in Kotlin: [${extra}] (${info.file})`
    );
  }
}

console.log(`uniffi records parsed: rust=${rust.size} kotlin_data_classes=${kt.size} compared=${compared}`);
if (problems.length) {
  console.error(`\nA14 ALARM -- ${problems.length} stale/mismatched record(s):`);
  for (const p of problems) console.error("  " + p);
  process.exit(1);
}
console.log("A14 OK: every uniffi::Record agrees with its generated Kotlin data class (count + names).");
process.exit(0);
