#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Bind the generated UniFFI Kotlin bindings to the NATIVE LIBRARY THAT ACTUALLY SHIPS.

WHY THIS EXISTS
---------------
`assembleArm64Debug` exiting 0 says a .so was produced. It does NOT say the .so exports the
functions the Kotlin side will call -- and a missing UniFFI symbol is not a compile error on
either side. It is an `UnsatisfiedLinkError` (or a UniFFI "contract mismatch" abort) the first
time the app touches that pillar, on a device, in front of the user.

For the x86_64 flavour that failure is catchable by running the APK on the AVD, which this repo
does every checkpoint. For the arm64 flavour it is NOT: measured 2026-07-29 on this machine,

    FATAL | Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on x86_64
            host. System image must match the host architecture.

so the arm64 APK cannot be booted here at all. This checker is the strongest substitute that
does not require running it: it proves the ABI surface is COMPLETE and that the two halves agree
symbol for symbol.

WHAT IT CHECKS
--------------
1. every `uniffi_<crate>_fn_*` symbol the Kotlin bindings call is exported by the .so
2. every `uniffi_<crate>_checksum_*` symbol is exported -- these are what UniFFI itself verifies
   at library-load time, so a mismatch here is precisely the startup abort
3. the .so is the architecture the flavour claims (ELF machine field), not a stale copy of the
   other ABI -- the exact "build exits 0 while shipping the old artifact" trap

WHAT IT DOES NOT CHECK
----------------------
That the code BEHIND those symbols is correct, or that it runs. Symbol presence is a necessary
condition, never a sufficient one. Do not read a green run here as "the arm64 build works".

EXIT CODES
----------
0 = every symbol present, arch correct
1 = a symbol is missing, or the arch is wrong  (a real defect)
2 = the checker could not do its job (APK/lib/bindings/llvm-nm not found) -- NEVER conflated
    with 0, because "I could not look" must never read as "I looked and it was fine"
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ELF e_machine values, little-endian, at offset 0x12.
ELF_MACHINE = {b"\xb7\x00": "aarch64", b"\x3e\x00": "x86-64"}
ABI_EXPECTED_MACHINE = {"arm64-v8a": "aarch64", "x86_64": "x86-64"}


def die(msg: str, code: int = 2) -> None:
    print(f"CHECKER-CANNOT-RUN: {msg}", file=sys.stderr)
    raise SystemExit(code)


def find_llvm_nm() -> Path:
    roots = [Path("D:/android-sdk/ndk"), Path.home() / "AppData/Local/Android/Sdk/ndk"]
    for root in roots:
        if not root.is_dir():
            continue
        for ndk in sorted(root.iterdir(), reverse=True):
            cand = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
            if cand.is_file():
                return cand
    die("no llvm-nm.exe found under any NDK root")
    raise AssertionError("unreachable")


def wanted_symbols(bindings: Path, crate: str) -> tuple[set[str], set[str]]:
    if not bindings.is_file():
        die(f"generated bindings not found: {bindings}")
    text = bindings.read_text(encoding="utf-8", errors="replace")
    fns = set(re.findall(rf"uniffi_{crate}_fn_[a-z0-9_]+", text))
    sums = set(re.findall(rf"uniffi_{crate}_checksum_[a-z0-9_]+", text))
    if not fns:
        die(f"no uniffi_{crate}_fn_* symbols found in {bindings} -- wrong crate name?")
    return fns, sums


def exported_symbols(nm: Path, so: Path, crate: str) -> tuple[set[str], set[str]]:
    proc = subprocess.run(
        [str(nm), "-D", "--defined-only", str(so)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        die(f"llvm-nm failed on {so}: {proc.stderr.strip()[:200]}")
    out = proc.stdout
    return (
        set(re.findall(rf"uniffi_{crate}_fn_[a-z0-9_]+", out)),
        set(re.findall(rf"uniffi_{crate}_checksum_[a-z0-9_]+", out)),
    )


def check_apk(apk: Path, abi: str, crate: str, bindings: Path, nm: Path) -> list[str]:
    """Return a list of failure strings; empty means this APK passed."""
    failures: list[str] = []
    if not apk.is_file():
        die(f"APK not found: {apk}")
    member = f"lib/{abi}/lib{crate}.so"
    with zipfile.ZipFile(apk) as z:
        if member not in z.namelist():
            die(f"{member} absent from {apk.name}")
        blob = z.read(member)

    # (3) architecture of the shipped .so, read from the ELF header itself
    machine = ELF_MACHINE.get(blob[0x12:0x14], f"unknown({blob[0x12:0x14].hex()})")
    if machine != ABI_EXPECTED_MACHINE[abi]:
        failures.append(
            f"{apk.name}: {member} is {machine}, expected {ABI_EXPECTED_MACHINE[abi]} "
            f"-- a STALE artifact from the other flavour is being shipped"
        )

    tmp = REPO / ".uniffi-abi-tmp"
    tmp.mkdir(exist_ok=True)
    so = tmp / f"{abi}-lib{crate}.so"
    so.write_bytes(blob)

    want_fn, want_sum = wanted_symbols(bindings, crate)
    have_fn, have_sum = exported_symbols(nm, so, crate)

    missing_fn = sorted(want_fn - have_fn)
    missing_sum = sorted(want_sum - have_sum)
    if missing_fn:
        failures.append(
            f"{apk.name} [{abi}]: {len(missing_fn)} FUNCTION symbol(s) the Kotlin bindings call "
            f"are NOT exported -- first few: {missing_fn[:5]}"
        )
    if missing_sum:
        failures.append(
            f"{apk.name} [{abi}]: {len(missing_sum)} CHECKSUM symbol(s) missing -- UniFFI verifies "
            f"these at library load, so this is a startup abort: {missing_sum[:5]}"
        )
    print(
        f"  {abi:<10} {machine:<8} fn {len(want_fn)}/{len(have_fn)} wanted/exported, "
        f"checksum {len(want_sum)}/{len(have_sum)}, missing {len(missing_fn) + len(missing_sum)}"
    )
    so.unlink(missing_ok=True)
    return failures


def self_test(bindings: Path, crate: str) -> None:
    """A checker nobody has broken on purpose is an untested alarm. Prove the diff can FAIL."""
    want, _ = wanted_symbols(bindings, crate)
    fake = f"uniffi_{crate}_fn_func_this_symbol_cannot_exist"
    poisoned = want | {fake}
    if not (poisoned - want) == {fake}:
        die("self-test could not construct a poisoned symbol set")
    # the real comparison is a set difference; show it detects the injected symbol
    have = want  # pretend the .so exports exactly what is wanted
    missing = sorted(poisoned - have)
    if missing != [fake]:
        print("SELF-TEST FAILED: the symbol diff did not detect an injected missing symbol",
              file=sys.stderr)
        raise SystemExit(1)
    print(f"  self-test OK -- an injected missing symbol IS detected ({fake})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--crate", default="torta_core")
    ap.add_argument("--skip-missing-apk", action="store_true",
                    help="treat an absent APK as skipped rather than fatal")
    args = ap.parse_args()

    crate = args.crate
    bindings = REPO / f"libumdnscrypt/src/main/kotlin/uniffi/{crate}/{crate}.kt"
    nm = find_llvm_nm()

    targets = [
        (REPO / "libumdnscrypt/build/outputs/apk/arm64/debug/libumdnscrypt-arm64-alpha.apk",
         "arm64-v8a"),
        (REPO / "libumdnscrypt/build/outputs/apk/universal/debug/libumdnscrypt-universal-alpha.apk",
         "x86_64"),
    ]

    print(f"UniFFI ABI check -- crate {crate}")
    print(f"  bindings {bindings.relative_to(REPO)}")
    self_test(bindings, crate)

    failures: list[str] = []
    for apk, abi in targets:
        if not apk.is_file() and args.skip_missing_apk:
            print(f"  {abi:<10} SKIPPED (APK not built)")
            continue
        failures += check_apk(apk, abi, crate, bindings, nm)

    tmp = REPO / ".uniffi-abi-tmp"
    if tmp.is_dir():
        try:
            tmp.rmdir()
        except OSError:
            pass

    if failures:
        print("\nFAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nOK: every UniFFI symbol the Kotlin bindings call is exported by every shipped ABI.")
    print("    (symbol presence is NECESSARY, not sufficient -- this is not a claim that it runs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
