<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2 -->
<!-- Copyright 2026 Saimonokuma. -->

<div align="center">

# 🔒 Security Policy

**Yeah! Tortä · Nova-Violet Role**

*We would rather tell you the limits than have you discover them*

</div>

---

## Status: this is an ALPHA

**Do not rely on Yeah! Tortä as your only protection for anything that matters.**
It is a pre-release. Pillars are being added, and the project's own `README.md`
names — in a table, on the front page — the pillar that is currently *not* proven.
That honesty is the point, and it is also the warning.

## What this software does to your device

It runs a **VPN service** and a **userspace network stack**. That is the security
surface, and it is stated first because it is what deserves auditing before you
install anything here.

| capability | what it means in practice |
|:--|:--|
| `BIND_VPN_SERVICE` | every packet your device sends can pass through this app's tun interface |
| a userspace forwarder | TCP/UDP are parsed and forwarded in-process (`rust/torta_core/src/forwarder/`) |
| a local DNS resolver | queries are answered, cached, denied or forwarded by this app |
| a loopback HTTP server | **opt-in, off by default** — Centauri's local CDN binds `127.0.0.1:<ephemeral>` |
| a device-local CA | **opt-in** — Centauri mints a CA to serve HTTPS CDN assets locally |
| optional ADB elevation | **opt-in** — WIRE CAKE INU acquires extra capability explicitly and reversibly |

No root is required for the core engine.

### The device CA deserves its own paragraph

If you enable Centauri's HTTPS leg, the app mints a certificate authority and asks
you to trust it. **A trusted CA can, in principle, impersonate any site to your
device.** This one is generated on-device, never leaves it, and the code refuses to
use it unless the certificate it is presented with is **byte-identical** to the one
in app storage — a same-name CA is explicitly rejected, and that property is proved
in Lean (`CloakTrustIdentity.lean`, 12 theorems) after a real incident in which
three separately-minted CAs shared an identical subject and filename.

If that trade is not one you want, leave Centauri off. It is off by default.

### What it does not do

It does not phone home, does not download executable code, and does not require an
account. Blocklists and catalogs are data, and the Centauri catalog is
**minisign-signed and hash-verified** before a single byte is served.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository
(*Security → Report a vulnerability*), or a private advisory. Include:

- what you did, exactly — commands, taps, the build you were on
- what you observed, with the real output (`cache/query.log` rows, `adb logcat`,
  a packet capture)
- what you expected instead
- your assessment of impact

You will get an acknowledgement. If the report is valid you will be credited by
name unless you ask not to be.

### What counts as a vulnerability here, beyond the obvious

This project treats a **false green as a security defect**, not a cosmetic one.
The following are in scope and are wanted:

* A pillar that reports itself active while doing nothing — a counter that cannot
  move, a dashboard reading LIVE on the strength of a metric that measures
  something else. (This has happened: `cloak_actions` was read as evidence Centauri
  was serving, and it counts blocklist sinkholes.)
* A gate that fails **open**. Anything that should deny and instead permits when a
  component is missing, unreachable, or throwing.
* A **leak past the engine** — a query, or a connection, that escapes attribution:
  the client-DoH bypass class of problem, where an app resolves through its own
  encrypted channel and every pillar goes blind at once.
* A **black hole**: interception that drops traffic it cannot serve. A dropped
  connection caused by a feature being armed is worse than the feature being off.
* An instrument that cannot fail. If you can show a check passes on deliberately
  broken input, that is a real finding.

## Supported versions

Only the latest pre-release. Until 1.0 there are no backports.

## Threat model, stated honestly

Yeah! Tortä raises the cost of **passive DNS observation and tracking** by
encrypting transport, rotating upstreams, denying known-bad names, and serving
common CDN assets locally so the upstream sees at most one request.

It is **not** anonymity software. It does not hide your IP address from the sites
you visit, does not defend against a compromised device, and does not protect
against an adversary who controls the operating system or the app you are browsing
with. If your threat model needs that, please use [Tor](https://www.torproject.org/) —
we would much rather point you somewhere better suited than have you rely on us for
something we do not do.

---

<div align="center">

### 🍰 Yeah! Tortä

*Thank you for looking closely. That is the whole idea.*

© 2026 Nova-Violet Role · Non-Profit Organization

*Created with ❤️ for the advancement of human understanding*

</div>

---

<!-- TAGS:BEGIN generated from .github/tags.txt -- do not hand-edit -->
<sub>

**#security** · **#security-policy** · **#responsible-disclosure** · **#vulnerability-reporting** · **#threat-model** · **#certificate-authority** · **#tls** · **#fail-closed** · **#minisign** · **#dns** · **#dns-privacy** · **#dnscrypt** · **#doh** · **#android** · **#rust** · **#kotlin** · **#slint** · **#adblock** · **#blocklist** · **#dns-server** · **#privacy** · **#cdn** · **#formal-verification** · **#lean4** · **#vpn** · **#no-root** · **#uniffi** · **#dns-resolver** · **#android-app** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#homograph** · **#rebind** · **#warden** · **#local-cdn** · **#content-addressed** · **#dns-filtering** · **#network-security** · **#vpn-service** · **#tun** · **#post-quantum** · **#open-source** · **#agpl** · **#eupl** · **#alpha** · **#pre-release**

*Tags are generated from [`.github/tags.txt`](.github/tags.txt) by the Meta Hashtag Manager — every one names something present in this tree.*

</sub>
<!-- TAGS:END -->
