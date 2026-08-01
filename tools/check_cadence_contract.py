#!/usr/bin/env -S uv run --script
# This file is part of Yeah! Tortä.
# SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
# Copyright 2026 Saimonokuma.
#
# THE ROTATION CADENCE CONTRACT CHECKER.
#
# The rotation cadence band is stated in THREE files, in TWO languages, and nothing until now
# noticed when they disagreed:
#
#   * RotationManager.kt      MIN_CADENCE_MINUTES / MAX_CADENCE_MINUTES / DEFAULT_CADENCE_MINUTES
#                             -- the only place the clamp is ENFORCED (readCadenceMs, at the read
#                             site, so any writer or a hand-edited prefs XML is caught).
#   * TortaPillarBridge.kt    CADENCE_DEFAULT_MIN -- the fallback the SLINT write path substitutes
#                             for a non-positive value.
#   * rotation_settings.slint the five preset chips the user can actually tap, plus the
#                             `preset-floor` the "below the floor" warning banner compares against.
#
# A drift between them does not fail to compile and does not fail a test. It shows up as a chip
# that silently resolves to a different cadence than its own label, or a warning banner that fires
# on legal values, or an unset install quietly getting the floor while the UI keeps saying
# "default 30 min".
#
# WHAT IS PROVEN vs WHAT IS CHECKED HERE. The properties that hold for ALL inputs -- the clamp
# lands in the band for any Int, the default survives its own clamp, every preset is honoured
# unchanged, the presets stay distinct, the clamp is idempotent and monotone -- are THEOREMS in
# D:\Lean\proofs\Proofs\RotationCadenceClamp.lean, mutation-tested. This script does the one thing
# a theorem cannot: it reads the REAL constants out of the REAL files and checks that the numbers
# the theorems were proven about are still the numbers that ship.
#
# Run:  uv run tools/check_cadence_contract.py
# Exit: 0 = the contract holds, 1 = a violation (printed with file:line), 2 = a source file or a
#       constant could not be found at all (a MOVED constant must fail loudly, never silently pass).

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ROTATION_MANAGER = ROOT / "libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/dns_engine/RotationManager.kt"
PILLAR_BRIDGE = ROOT / "libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/slint/TortaPillarBridge.kt"
ROTATION_SLINT = ROOT / "rust/torta_ui/ui/rotation_settings.slint"

failures: list[str] = []


def read(path: Path) -> str:
    if not path.is_file():
        print(f"FATAL: source file not found: {path}", file=sys.stderr)
        sys.exit(2)
    return path.read_text(encoding="utf-8", errors="replace")


def grab_int(text: str, path: Path, pattern: str, what: str) -> int:
    """Extract exactly one integer. A constant that has MOVED or been renamed exits 2 rather than
    being treated as absent-and-therefore-fine -- the failure mode that makes a checker decorative."""
    hits = re.findall(pattern, text)
    if len(hits) != 1:
        print(
            f"FATAL: expected exactly 1 match for {what} in {path.name}, found {len(hits)}.\n"
            f"       pattern: {pattern}\n"
            f"       The constant was renamed, moved or duplicated. Fix this script AND check the\n"
            f"       Lean model in Proofs/RotationCadenceClamp.lean still describes reality.",
            file=sys.stderr,
        )
        sys.exit(2)
    return int(hits[0])


def check(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


kt = read(ROTATION_MANAGER)
bridge = read(PILLAR_BRIDGE)
slint = read(ROTATION_SLINT)

min_min = grab_int(kt, ROTATION_MANAGER, r"const val MIN_CADENCE_MINUTES\s*=\s*(\d+)", "MIN_CADENCE_MINUTES")
max_min = grab_int(kt, ROTATION_MANAGER, r"const val MAX_CADENCE_MINUTES\s*=\s*(\d+)", "MAX_CADENCE_MINUTES")
def_min = grab_int(kt, ROTATION_MANAGER, r"const val DEFAULT_CADENCE_MINUTES\s*=\s*(\d+)", "DEFAULT_CADENCE_MINUTES")
bridge_def = grab_int(bridge, PILLAR_BRIDGE, r"const val CADENCE_DEFAULT_MIN\s*=\s*(\d+)", "CADENCE_DEFAULT_MIN")
slint_floor = grab_int(slint, ROTATION_SLINT, r"property <int> preset-floor:\s*(\d+)", "preset-floor")

# The chips the user can tap, in seconds. The chips do NOT carry literals -- each binds
# `secs: root.preset-<name>` -- so the values come from the property declarations, and the count of
# BINDINGS is cross-checked against the count of DECLARATIONS. That pairing is the point: a sixth
# preset property declared but never bound to a chip (or a chip bound to a property that no longer
# exists) is exactly the kind of half-landed edit that leaves a control unreachable, which is the
# defect class already found twice in this pane.
presets = [int(s) for s in re.findall(r"property <int> preset-[\w-]+:\s*(\d+)\s*;", slint)]
bound_chips = len(re.findall(r"secs:\s*root\.preset-[\w-]+\s*;", slint))
if bound_chips != len(presets):
    print(
        f"FATAL: {len(presets)} preset properties declared but {bound_chips} chips bind one in "
        f"{ROTATION_SLINT.name}. Either a preset has no chip (unreachable cadence) or a chip binds "
        f"a property that no longer exists.",
        file=sys.stderr,
    )
    sys.exit(2)
if len(presets) < 5:
    print(
        f"FATAL: found only {len(presets)} cadence presets in {ROTATION_SLINT.name}; expected the "
        f"five chips. The pane was restructured -- re-read it and update this script and the Lean "
        f"`uiPresetSeconds` list together.",
        file=sys.stderr,
    )
    sys.exit(2)

# ---- 1. The band is well formed, and the DEFAULT survives its own clamp. -------------------------
# readCadenceMs substitutes DEFAULT *before* coerceIn, so a floor above the default would silently
# turn every unset install into the floor while the UI kept advertising the default.
check(min_min <= max_min, f"band inverted: MIN_CADENCE_MINUTES={min_min} > MAX_CADENCE_MINUTES={max_min}")
check(
    min_min <= def_min <= max_min,
    f"DEFAULT_CADENCE_MINUTES={def_min} is OUTSIDE [{min_min}, {max_min}] -- it would be silently "
    f"clamped, and every 'default {def_min} min' string in the UI would be a lie",
)

# ---- 2. The two Kotlin defaults agree. -----------------------------------------------------------
# The bridge substitutes its own constant for a non-positive write; if it disagreed with the
# manager's, the value written and the value scheduled would differ with nothing reporting it.
check(
    bridge_def == def_min,
    f"default drift: TortaPillarBridge.CADENCE_DEFAULT_MIN={bridge_def} but "
    f"RotationManager.DEFAULT_CADENCE_MINUTES={def_min}",
)

# ---- 3. The SLINT floor is the Kotlin floor. -----------------------------------------------------
# The pane's warn-cadence-clamped banner compares against preset-floor. If it drifted BELOW the real
# floor, the pane would stay silent while the engine clamped; ABOVE it, the banner would cry on
# perfectly legal cadences.
check(
    slint_floor == min_min * 60,
    f"floor drift: rotation_settings.slint preset-floor={slint_floor}s but "
    f"MIN_CADENCE_MINUTES={min_min} ({min_min * 60}s)",
)

# ---- 4. EVERY chip the user can tap is honoured by the engine, unchanged. -------------------------
# This is the theorem `every_ui_preset_survives_the_clamp` checked against the shipping numbers.
for secs in presets:
    minutes = secs // 60
    check(secs % 60 == 0, f"preset {secs}s is not a whole number of minutes; the pref is minute-granular")
    check(
        min_min <= minutes <= max_min,
        f"preset {secs}s ({minutes} min) lies OUTSIDE the enforced band [{min_min}, {max_min}] -- "
        f"the chip advertises a cadence the engine will silently replace",
    )

# ---- 4b. The rotation DASHBOARD's own quick-pick row. ---------------------------------------------
# Found by DRIVING the live dashboard on the AVD, not by reading: rotation.slint offers a SECOND,
# different set of cadence chips -- `for m in [5, 15, 30, 60]` -- in MINUTES, not seconds. They write
# the same RESOLVER_ROTATION_CADENCE_MINUTES pref. The first version of this checker validated only
# the settings pane, so a `0` or `1` added to THIS row would have been tappable, silently clamped,
# and invisible to every check. Every cadence the user can pick belongs here, wherever the chip lives.
ROTATION_DASH = ROOT / "rust/torta_ui/ui/rotation.slint"
dash_src = read(ROTATION_DASH)
dash_m = re.search(r"for m in \[([0-9, ]+)\]", dash_src)
if not dash_m:
    print(
        f"FATAL: could not find the dashboard cadence chip row (`for m in [...]`) in "
        f"{ROTATION_DASH.name}. It was restructured -- re-read it and update this script and the "
        f"Lean `dashPresetMinutes` list together.",
        file=sys.stderr,
    )
    sys.exit(2)
dash_presets = [int(x) for x in dash_m.group(1).split(",")]
for minutes in dash_presets:
    check(
        min_min <= minutes <= max_min,
        f"dashboard preset {minutes} min lies OUTSIDE the enforced band [{min_min}, {max_min}] -- "
        f"the chip advertises a cadence the engine will silently replace",
    )
dash_clamped = [max(min_min, min(max_min, m)) for m in dash_presets]
check(
    len(set(dash_clamped)) == len(dash_clamped),
    f"two or more DASHBOARD presets collapse onto the same cadence after clamping: {dash_clamped}",
)

# ---- 5. The chips stay distinct after clamping. ---------------------------------------------------
clamped = [max(min_min, min(max_min, s // 60)) for s in presets]
check(
    len(set(clamped)) == len(clamped),
    f"two or more presets collapse onto the same cadence after clamping: {clamped} -- "
    f"duplicate buttons doing the same thing",
)

# ---- 6. The Lean model still describes the shipping numbers. --------------------------------------
# The theorems are only about the app if their constants are the app's constants.
LEAN = Path("D:/Lean/proofs/Proofs/RotationCadenceClamp.lean")
if LEAN.is_file():
    lean_src = LEAN.read_text(encoding="utf-8", errors="replace")

    def lean_int(name: str) -> int | None:
        m = re.search(rf"def {name} : Nat := (\d+)", lean_src)
        return int(m.group(1)) if m else None

    for lean_name, kt_val, kt_name in (
        ("minMinutes", min_min, "MIN_CADENCE_MINUTES"),
        ("maxMinutes", max_min, "MAX_CADENCE_MINUTES"),
        ("defaultMinutes", def_min, "DEFAULT_CADENCE_MINUTES"),
    ):
        got = lean_int(lean_name)
        check(
            got == kt_val,
            f"Lean model drift: RotationCadenceClamp.{lean_name}={got} but {kt_name}={kt_val} -- "
            f"the theorems are no longer about the shipping code",
        )

    lean_presets = re.search(r"def uiPresetSeconds : List Nat := \[([0-9, ]+)\]", lean_src)
    if lean_presets:
        modelled = [int(x) for x in lean_presets.group(1).split(",")]
        check(
            sorted(modelled) == sorted(presets),
            f"Lean model drift: uiPresetSeconds={sorted(modelled)} but the pane offers {sorted(presets)}",
        )

    lean_dash = re.search(r"def dashPresetMinutes : List Nat := \[([0-9, ]+)\]", lean_src)
    if lean_dash:
        modelled_dash = [int(x) for x in lean_dash.group(1).split(",")]
        check(
            sorted(modelled_dash) == sorted(dash_presets),
            f"Lean model drift: dashPresetMinutes={sorted(modelled_dash)} but the dashboard offers "
            f"{sorted(dash_presets)}",
        )
else:
    print(f"note: Lean model not present at {LEAN} (proofs live outside this repo) -- skipping section 6")

print(f"cadence band      : [{min_min}, {max_min}] minutes, default {def_min}")
print(f"slint preset floor: {slint_floor}s")
print(f"presets (seconds) : {presets}")
print(f"presets (clamped) : {clamped} minutes")
print(f"dash presets (min): {dash_presets}")

if failures:
    print(f"\nCADENCE CONTRACT VIOLATED ({len(failures)}):", file=sys.stderr)
    for f in failures:
        print(f"  * {f}", file=sys.stderr)
    sys.exit(1)

print("\ncadence contract OK")
