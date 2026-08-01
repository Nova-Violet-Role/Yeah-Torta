# AVD hazards — things that cost real time, measured on this rig

Each entry is something that ACTUALLY happened here, with the symptom that misled and the recovery
that worked. Not advice; a logbook.

---

## H1 — Tapping "Wireless debugging" in Settings WEDGES adb, and the wedge SURVIVES a cold boot

**Symptom.** `adb devices` reports `emulator-5554  offline` forever. `adb reconnect`, `kill-server`,
`connect localhost:5555` all fail. A cold boot with `-no-snapshot-load` does NOT fix it. The qemu
process is alive and holds both 5554 and 5555, so the VM is fine — only the transport is dead.

**Cause.** Enabling wireless debugging persists `adb_wifi_enabled=1` in the guest's settings, which
survives userdata across reboots, and adbd comes back up in a TLS mode the emulator's built-in
transport cannot complete.

**What misled.** "offline" reads like a boot-in-progress. It is not: seven minutes of polling
`sys.boot_completed` returned empty every time because the shell channel itself was gone. A process
listing proved the VM alive, which is what separated "still booting" from "transport dead".

**Recovery (the only one that worked).**

    stop qemu + the emulator launcher BY EXACT PID   (never by pattern -- see H2)
    emulator -avd <avd> -no-boot-anim -no-snapshot-load -wipe-data

`-wipe-data` is required; without it the poisoned setting comes straight back. Confirmed: after the
wipe `adb devices` showed `device` within 60 s and `settings get global adb_wifi_enabled` read `0`.

**Cost.** The whole userdata: the app, the query ledger, WARDEN state, the INU store. All of it is
reproducible (`adb install`, `tools/avd-ipv6`, re-arm through the UI), which is the only reason the
wipe is acceptable. Do NOT do this on a rig holding a measurement you have not yet recorded.

**CORRECTION — the first version of this entry gave backwards advice.** It said "don't enable
wireless debugging on the AVD at all". That is wrong, and the Socio caught it: **WIRE CAKE INU *IS*
the wireless-debugging pillar.** `WireCakeInuService.kt:43` — it discovers the randomly-chosen
`_adb-tls-pairing._tcp` port and takes the **6-digit pairing code** the user types in the shade.
Wireless debugging is not a hazard the pillar must avoid; it is the mechanism the pillar EXISTS to
drive. "Never turn it on" would disarm the pillar to protect my observation channel — exactly the
kind of closure the master forbids.

**What is actually true:** the pillar pairs over **loopback, on the device itself** (self-ADB, no
companion app, no root). It does NOT need the host's adb at all. The only casualty of enabling
wireless debugging is MY OBSERVATION CHANNEL — the emulator's console-backed transport goes offline
because guest adbd switches to the TLS/mDNS path that slirp does not expose to the host.

So the real problem is not "wireless debugging breaks the AVD". It is:

> the emulator's adb transport and the guest's TLS adb mode are mutually exclusive, so the AVD can
> either be OBSERVED by the host or PAIR with itself — and driving the pairing needs both.

That is a problem to SOLVE (host-side port redirection to the guest's TLS adb port, or driving the
pairing blind and restoring the setting afterwards), not a reason to leave the pillar off. The wipe
above is the recovery when it goes wrong, not the plan.

---

## H2 — Never stop a process by pattern

`Get-Process qemu* | Stop-Process` and `pkill -f` will match things you did not mean, and on this
machine a pattern kill has taken out the local proxy carrying the session's own API traffic. Read
the PID from a process listing, confirm its `StartTime`, and stop that ONE id.

---

## H3 — Three IPv6 instruments that returned confident false negatives

Recorded in full in the header of `tools/avd-ipv6`. Short form:

| instrument | why it lied |
|---|---|
| `ip -6 addr show scope global` | the guest address is `fec0::`, scope **site** — the filter deleted the evidence |
| `ping6` | slirp forwards **no ICMPv6**; 100% loss on a link where TCP works perfectly |
| `ip -6 route show` | Android routes from **per-network** tables; `show table eth0` had the default all along |

The lesson that generalises: **probe with the transport the app actually uses.** TCP works, so test
TCP (`toybox nc -6`). ICMP reachability is not TCP reachability.

---

## H4 — `lake build X | tail` reports tail's exit code, not the build's

Read `$?` / `$LASTEXITCODE` directly from the command itself, then inspect the output separately.
This has produced a false green here.

---

## H5 — Gradle packages from `jniLibs/`, NOT from the cargo target dir

A successful `cargo ndk build` does not mean the new library shipped. Copy it into
`libumdnscrypt/src/main/jniLibs/<abi>/`, assert the byte sizes match, THEN assemble — and check the
`.so` inside the APK. A stale library once made a correct UI fix look broken, and the obvious
"repair" would have damaged working code.
