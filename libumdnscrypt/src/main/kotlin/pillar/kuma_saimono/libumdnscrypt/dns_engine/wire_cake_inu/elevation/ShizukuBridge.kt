/*
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2

    Yeah! Tortä
    Copyright 2026 Saimonokuma

    This file is part of Yeah! Tortä, dual-licensed at your option under
    EITHER the GNU Affero General Public License, version 3 or later (see
    agpl-3.0.md), OR the European Union Public Licence, version 1.2 or later
    (see EUPL-LICENSE.txt).

    Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
 */

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

/**
 * The one-method seam onto the Shizuku API (P11 §2: "behind a one-method seam swappable to
 * `UserService` later").
 *
 * GROUND_TRUTH (build.gradle:196-199, measured at HEAD): `dev.rikka.shizuku:api` is **NOT** a
 * dependency today — only libadb-android 3.1.1 + sun-security-android 1.1 + conscrypt-android 2.5.3
 * are declared. Adding the dep is a tracked follow-up (it also needs the
 * `rikka.shizuku.ShizukuProvider` manifest provider + the `API_V23` permission). Until then the
 * adapter must keep the build GREEN **without** the dep, so this seam talks to the Shizuku binder
 * by **reflection only** — it never references a `dev.rikka.shizuku.*` type at compile time.
 *
 * When the dep lands, the production binding swaps [ReflectiveShizukuBridge] for a thin direct-call
 * implementation of this same interface; nothing else changes. self-ADB (the P6 path) stays the
 * working elevation channel in the meantime.
 *
 * No root, ever — Shizuku itself is a no-root user-service elevation; this is purely a bind onto
 * it.
 */
interface ShizukuBridge {

    /** Whether the Shizuku API classes are present on the classpath at all (dep added or not). */
    val apiPresent: Boolean

    /** True when a Shizuku/Sui service is connected and the binder answers `pingBinder`. */
    fun pingBinder(): Boolean

    /** True when this app already holds the Shizuku permission (no re-prompt needed). */
    fun hasPermission(): Boolean

    /**
     * Run one command through `Shizuku.newProcess(["sh","-c", command])`, wait for it, and return
     * the raw merged result (exit code + combined stdout/stderr). The caller is responsible for the
     * exit sentinel and for never concatenating user input into [command] (P11 §5.3).
     *
     * Returns null when the API is absent or the call fails — the adapter degrades honestly, it
     * never fabricates a success.
     */
    fun newProcess(command: String): RawProcessResult?

    // ---- deepened middle-man surface (Genesis: Shizuku-studied, reimplemented — ZERO bytes
    // copied) --
    // The reflective seam below reimplements the corpus middle-man contract. The Shizuku `api`
    // submodule is NOT checked out, so the method names are the established public Shizuku API
    // (README.md:52 names `ShizukuService#getUid`; the rest mirror the server `bindApplication`
    // reply
    // fields — ShizukuService.java:233-239 — that the api wrapper exposes). All degrade to
    // not-available without the dep, so they NEVER fabricate a grant/identity. Defaulted so a lean
    // fake need not implement them.

    /**
     * Ask the user for the one-tap permission — the REQUEST half of the handshake that
     * [hasPermission] only observes. Corpus flow: the app calls the API, the server raises the
     * manager confirmation UI (`ShizukuService.showPermissionConfirmation`,
     * ShizukuService.java:255-281) and later returns allowed/onetime
     * (`dispatchPermissionConfirmationResult`, :294-316). Reflection-only:
     * `Shizuku.requestPermission(int)`. Returns true if the ask was dispatched; false when the API
     * is absent (today) or the call fails — honest degrade, never a fake grant.
     */
    fun requestPermission(requestCode: Int): Boolean = false

    /**
     * Whether to show the "why we need this" rationale before re-asking (the user denied once).
     * Maps to the server `bindApplication` reply field
     * `BIND_APPLICATION_SHOULD_SHOW_REQUEST_PERMISSION_RATIONALE` (ShizukuService.java:239).
     * Reflection-only: `Shizuku.shouldShowRequestPermissionRationale()`.
     */
    fun shouldShowRationale(): Boolean = false

    /**
     * The privileged server's uid — the middle-man identity from the `bindApplication` reply
     * `BIND_APPLICATION_SERVER_UID` (ShizukuService.java:233 = `OsUtils.getUid()`). 2000 = the ADB
     * shell (our preferred, smaller-attack-surface path), 0 = root. README.md:52 names
     * `ShizukuService#getUid` as the way to "check if Shizuku is running user ADB".
     * Reflection-only: `Shizuku.getUid()`. Returns -1 when unknown/absent.
     */
    fun serverUid(): Int = -1

    /**
     * The privileged server's protocol version — the `bindApplication` reply
     * `BIND_APPLICATION_SERVER_VERSION` (ShizukuService.java:234). Lets the caller gate on server
     * capability (the modern typed-binder middle-man of README.md:30 is v11+). Reflection-only:
     * `Shizuku.getVersion()`. Returns -1 when unknown/absent.
     */
    fun serverVersion(): Int = -1

    /**
     * The privileged server's SELinux context — the `bindApplication` reply
     * `BIND_APPLICATION_SERVER_SECONTEXT` (ShizukuService.java:235). The honest domain the
     * privileged channel runs in (rounds out the uid/version/secontext identity triple).
     * Reflection-only: `Shizuku.getSELinuxContext()`. Null when unknown/absent.
     */
    fun seContext(): String? = null
}

/** Raw result of a Shizuku-spawned process: the merged stream plus the real exit code. */
data class RawProcessResult(val exit: Int, val output: String)

/**
 * Reflection-only [ShizukuBridge]. Resolves `rikka.shizuku.Shizuku` + `ShizukuProvider` lazily; if
 * they are absent (today's tree) every probe answers "not available" and [newProcess] returns null.
 * No `dev.rikka.shizuku.*` symbol appears here, so this compiles and ships GREEN with no new dep.
 */
class ReflectiveShizukuBridge : ShizukuBridge {

    private val shizukuClass: Class<*>? by lazy {
        runCatching { Class.forName("rikka.shizuku.Shizuku") }.getOrNull()
    }

    override val apiPresent: Boolean
        get() = shizukuClass != null

    override fun pingBinder(): Boolean = runCatching {
        val cls = shizukuClass ?: return false
        cls.getMethod("pingBinder").invoke(null) as? Boolean ?: false
    }
        .getOrDefault(false)

    override fun hasPermission(): Boolean = runCatching {
        val cls = shizukuClass ?: return false
        // Shizuku.checkSelfPermission() : Int (PackageManager.PERMISSION_GRANTED == 0)
        val granted = cls.getMethod("checkSelfPermission").invoke(null) as? Int ?: return false
        granted == 0
    }
        .getOrDefault(false)

    override fun newProcess(command: String): RawProcessResult? = runCatching {
        val cls = shizukuClass ?: return null
        // Reflective Shizuku.newProcess(String[] cmd, String[] env, String dir) :
        // ShizukuRemoteProcess
        val method =
            cls.getDeclaredMethod(
                    "newProcess",
                    Array<String>::class.java,
                    Array<String>::class.java,
                    String::class.java,
                )
                .apply { isAccessible = true }

        val argv = arrayOf("sh", "-c", command)
        val process = method.invoke(null, argv, null, null) ?: return null

        val output =
            process.javaClass.getMethod("getInputStream").invoke(process)?.let {
                (it as java.io.InputStream).bufferedReader().readText()
            } ?: ""
        val exit = process.javaClass.getMethod("waitFor").invoke(process) as? Int ?: -1

        RawProcessResult(exit, output)
    }
        .getOrNull()

    override fun requestPermission(requestCode: Int): Boolean = runCatching {
        val cls = shizukuClass ?: return false
        // Shizuku.requestPermission(int requestCode) : void
        cls.getMethod("requestPermission", Int::class.javaPrimitiveType).invoke(null, requestCode)
        true
    }
        .getOrDefault(false)

    override fun shouldShowRationale(): Boolean = runCatching {
        val cls = shizukuClass ?: return false
        // Shizuku.shouldShowRequestPermissionRationale() : boolean
        cls.getMethod("shouldShowRequestPermissionRationale").invoke(null) as? Boolean ?: false
    }
        .getOrDefault(false)

    override fun serverUid(): Int = runCatching {
        val cls = shizukuClass ?: return -1
        // Shizuku.getUid() : int (2000 = adb shell, 0 = root; README.md:52)
        cls.getMethod("getUid").invoke(null) as? Int ?: -1
    }
        .getOrDefault(-1)

    override fun serverVersion(): Int = runCatching {
        val cls = shizukuClass ?: return -1
        // Shizuku.getVersion() : int
        cls.getMethod("getVersion").invoke(null) as? Int ?: -1
    }
        .getOrDefault(-1)

    override fun seContext(): String? = runCatching {
        val cls = shizukuClass ?: return null
        // Shizuku.getSELinuxContext() : String
        cls.getMethod("getSELinuxContext").invoke(null) as? String
    }
        .getOrNull()
}
