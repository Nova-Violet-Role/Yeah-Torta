<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2 -->
<!-- Copyright 2026 Saimonokuma. -->

# Licence texts

**Yeah! Tortä is dual-licensed: `AGPL-3.0-or-later` OR `EUPL-1.2`, at your option.**
Take either one. You do not need permission to choose, and you do not have to comply
with both.

| file | licence |
|:--|:--|
| [`AGPL-3.0-or-later.txt`](AGPL-3.0-or-later.txt) | GNU Affero General Public License v3.0 or later |
| [`EUPL-1.2.txt`](EUPL-1.2.txt) | European Union Public Licence v1.2 |

The root [`LICENSE`](../LICENSE) file is a **copy of the AGPL text**, and it is there for
a mechanical reason worth writing down.

## Why this directory is called `legal/` and not `LICENSES/`

GitHub detects a repository's licence with the Ruby gem
[**licensee**](https://github.com/licensee/licensee). Measured here with licensee 10.0.0,
the same version GitHub uses:

| layout | detected |
|:--|:--|
| `LICENSE` alone | **AGPL-3.0** ✅ |
| `LICENSE` + `legal/*.txt` | **AGPL-3.0** ✅ |
| `LICENSE` + `LICENSES/*.txt` | `NOASSERTION` ❌ |
| `LICENSE` + `LICENSE-EUPL-1.2` | `NOASSERTION` ❌ |
| `LICENSE` with a 2-line dual-grant preamble | `NOASSERTION` ❌ |

licensee returns `NOASSERTION` whenever it finds **more than one distinct licence**, and
it scans `LICENSES/` and `licenses/` as licence directories. So the REUSE-style layout —
which is otherwise the correct one — makes GitHub show **no licence at all**, which is
strictly worse for a reader than showing one of the two with the second one documented.

Both of these matter and they conflict:

* **REUSE** wants `LICENSES/` and per-file SPDX headers.
* **GitHub** wants exactly one detectable licence file.

The choice made here is to keep the **per-file SPDX headers** — which is where the dual
grant is actually asserted, on every source file, machine-readable — and to rename the
directory so GitHub can display something. Every file in this project still says
`SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2` at its top, and that is the
authoritative statement.

> **The badge is not the licence.** GitHub's sidebar will say "AGPL-3.0". The actual grant
> is the disjunction, asserted in every file header, in `README.md`, and above. If those
> ever disagree, the SPDX headers win.
