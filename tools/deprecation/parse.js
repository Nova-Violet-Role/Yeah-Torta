// The ONE parser for Kotlin deprecation warnings. Required by depgate.js and depclass.js.
//
// WHY THIS FILE EXISTS. depgate.js and depclass.js each carried their own copy of
//
//     /w: file:\/\/\/(\S+?\.kt):(\d+):\d+\s+(.*)$/
//     decodeURIComponent(m[1]).split(/[\\/]/).pop()
//
// Identical today, and two things that can drift tomorrow. They are the front door of every number
// this project reports about the deprecation backlog: if the extraction is wrong, the ceiling gate
// compares correctly-computed nonsense, and Proofs/DeprecationKeying.lean proves a property of a
// model whose inputs never matched reality. A theorem about the comparison says nothing about the
// parse that feeds it.
//
// The failure directions are NOT symmetric, and that is worth stating because it is the reason this
// was a lower-priority risk than it looked:
//
//   * regex matches NOTHING          -> total 0 -> depgate's FLOOR (5) fires. Caught.
//   * symbols all collapse to one    -> per-key counts rise above baseline -> FAIL. Caught.
//   * message wording changes         -> keys become NEW -> FAIL. Caught, loudly.
//   * a symbol normalises to a DIFFERENT but still-plausible key -> silently miscounted. NOT caught.
//
// The last one is why this has a conformance corpus (parse-conformance.js) rather than a comment
// asserting the regex is right.
"use strict";

/** The prefixes Kotlin puts in front of a quoted declaration. Stripped so the key names the SYMBOL. */
const DECL_PREFIX = /^(?:static field |val |var |fun |class )/;

/**
 * Parse one line of Kotlin compiler output.
 * @returns {{base:string, line:number, message:string, symbol:string}|null} null if not a warning.
 */
function parseWarningLine(l) {
  const m = l.match(/w: file:\/\/\/(\S+?\.kt):(\d+):\d+\s+(.*)$/);
  if (!m) return null;

  // decodeURIComponent, because the compiler percent-encodes the path and this repository's own
  // directory name contains a non-ASCII character. A raw split on that path silently yields a
  // basename that matches no file on disk -- measured earlier in this project when a `file:///`
  // URL broke every fs.readFileSync in a sibling tool.
  let decoded;
  try { decoded = decodeURIComponent(m[1]); } catch (_e) { decoded = m[1]; }
  const base = decoded.split(/[\\/]/).pop();

  const message = m[3];
  const sm = message.match(/'([^']+)'/);
  // FALLBACK when the compiler emitted no quoted declaration. Kept because dropping the line
  // entirely would UNDERCOUNT, and undercounting is the direction that makes a gate pass wrongly.
  let symbol = sm ? sm[1] : message.slice(0, 40);
  symbol = symbol.replace(DECL_PREFIX, "");
  // A GENERIC declaration puts its type parameters before the name:
  //     'fun <T : Parcelable!> getParcelableExtra(p0: String!): T?'
  // Cutting at the first ':' then yields "<T" -- the method name is GONE, and EVERY generic
  // deprecation in a file collapses onto the single key "<file>|<T". Found 2026-08-01 while
  // watching keys disappear during the IntentCompat migration: the log showed
  // "ModulesReceiver.kt|<T  1 -> 0", which names no method at all.
  //
  // This is precisely the failure mode parse.js's own header calls the only SILENTLY SURVIVABLE
  // one: the key is stable and plausible, so no floor trips and no gate reddens, while two
  // distinct methods share one baseline slot and one of them can be replaced by the other without
  // the ceiling noticing. Strip the type-parameter list so the name survives.
  symbol = symbol.replace(/^<[^>]*>\s*/, "");
  symbol = symbol.replace(/[:(].*$/, "").trim();

  return { base, line: Number(m[2]), message, symbol };
}

/** The gate's comparison key. Deliberately free of the line number -- see DeprecationKeying.lean. */
function keyOf(p) { return p.base + "|" + p.symbol; }

module.exports = { parseWarningLine, keyOf, DECL_PREFIX };
