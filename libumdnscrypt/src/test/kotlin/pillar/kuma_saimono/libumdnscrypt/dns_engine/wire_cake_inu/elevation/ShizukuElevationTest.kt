/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

/*
   This file is part of Yeah! Tortä. GPL-3.0-or-later. Copyright 2026 Saimonokuma.
*/

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu.elevation

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM proofs for the Shizuku adapter. No Android, no real Shizuku binder — a fake
 * [ShizukuBridge] stands in. Covers: the exit-sentinel codec, the availability state machine, the
 * build-green-without -the-dep honest degrade, and the no-user-input-concatenation safety (P11
 * §5.3). LIVE Shizuku E2E is deferred to the tracked device witness (the emu is a LeakCanary tar
 * pit).
 */
class ShizukuElevationTest {

    /** A scriptable fake of the reflection seam — never touches a real binder. */
    private class FakeBridge(
        override val apiPresent: Boolean = true,
        private val pinging: Boolean = true,
        private val permitted: Boolean = true,
        private val responder: ((String) -> RawProcessResult?)? = null,
    ) : ShizukuBridge {
        val seenCommands = mutableListOf<String>()

        override fun pingBinder() = pinging

        override fun hasPermission() = permitted

        override fun newProcess(command: String): RawProcessResult? {
            seenCommands += command
            return responder?.invoke(command)
        }
    }

    // ---- sentinel codec -----------------------------------------------------

    @Test
    fun `wrap appends the exit sentinel`() {
        assertEquals(
            "settings get secure always_on_vpn_app; echo \"${ShizukuSentinel.MARKER} \$?\"",
            ShizukuSentinel.wrap("settings get secure always_on_vpn_app"),
        )
    }

    @Test
    fun `parse recovers exit code and strips the sentinel line`() {
        val raw =
            RawProcessResult(exit = 0, output = "app.torta.yeah\n${ShizukuSentinel.MARKER} 0\n")
        val res = ShizukuSentinel.parse(raw)
        assertEquals(0, res.exit)
        assertEquals("app.torta.yeah", res.stdout)
        assertTrue(res.ok)
    }

    @Test
    fun `parse trusts the sentinel exit over the process exit when they disagree`() {
        // ROM swallowed the real exit (process says 0) but the shell sentinel reports failure.
        val raw = RawProcessResult(exit = 0, output = "null\n${ShizukuSentinel.MARKER} 1\n")
        val res = ShizukuSentinel.parse(raw)
        assertEquals(1, res.exit)
        assertFalse(res.ok)
        assertEquals("null", res.stdout)
    }

    @Test
    fun `parse falls back to process exit when no sentinel is present`() {
        val raw = RawProcessResult(exit = 7, output = "garbled output with no marker")
        val res = ShizukuSentinel.parse(raw)
        assertEquals(7, res.exit)
        assertEquals("garbled output with no marker", res.stdout)
    }

    @Test
    fun `parse preserves multi-line stdout above the sentinel`() {
        val raw = RawProcessResult(exit = 0, output = "line1\nline2\n${ShizukuSentinel.MARKER} 0\n")
        assertEquals("line1\nline2", ShizukuSentinel.parse(raw).stdout)
    }

    // ---- availability state machine -----------------------------------------

    @Test
    fun `availability is NOT_INSTALLED when the api is absent`() {
        val e = ShizukuElevation(FakeBridge(apiPresent = false), Dispatchers.Unconfined)
        assertEquals(ShizukuAvailability.NOT_INSTALLED, e.availability())
        assertFalse(e.isReady)
    }

    @Test
    fun `availability is NOT_RUNNING when present but binder does not answer`() {
        val e = ShizukuElevation(FakeBridge(pinging = false), Dispatchers.Unconfined)
        assertEquals(ShizukuAvailability.NOT_RUNNING, e.availability())
    }

    @Test
    fun `availability is PERMISSION_NEEDED when running but ungranted`() {
        val e = ShizukuElevation(FakeBridge(permitted = false), Dispatchers.Unconfined)
        assertEquals(ShizukuAvailability.PERMISSION_NEEDED, e.availability())
    }

    @Test
    fun `availability is READY when present running and granted`() {
        val e = ShizukuElevation(FakeBridge(), Dispatchers.Unconfined)
        assertEquals(ShizukuAvailability.READY, e.availability())
        assertTrue(e.isReady)
        assertTrue(ShizukuAvailability.READY.usable)
    }

    // ---- connect + honest degrade -------------------------------------------

    @Test
    fun `connect fails honestly when not ready`() = runBlocking {
        val e = ShizukuElevation(FakeBridge(apiPresent = false), Dispatchers.Unconfined)
        val result = e.connect()
        assertTrue(result.isFailure)
        assertEquals(
            ShizukuAvailability.NOT_INSTALLED.honestReason,
            result.exceptionOrNull()?.message,
        )
    }

    @Test
    fun `reflective bridge degrades to absent on the real classpath without the dep`() {
        // GROUND_TRUTH: dev.rikka.shizuku:api is NOT a dependency at HEAD (build.gradle:196-199) →
        // the real reflective bridge must report absent and never spawn, keeping the build/runtime
        // green.
        val bridge = ReflectiveShizukuBridge()
        assertFalse("rikka.shizuku.Shizuku must be absent without the dep", bridge.apiPresent)
        assertFalse(bridge.pingBinder())
        assertFalse(bridge.hasPermission())
        assertNull(bridge.newProcess("settings get secure always_on_vpn_app"))
        // The deepened middle-man surface must ALSO degrade honestly (no dep → no fabricated
        // grant/identity): the reflection resolves nothing, so every probe answers "not available".
        assertFalse(bridge.requestPermission(ShizukuElevation.REQUEST_CODE_ONE_TAP))
        assertFalse(bridge.shouldShowRationale())
        assertEquals(-1, bridge.serverUid())
        assertEquals(-1, bridge.serverVersion())
        assertNull(bridge.seContext())
    }

    // ---- deepened surface: permission handshake + middle-man identity + linkToDeath -------------

    @Test
    fun `serverPrivilege decodes the middle-man server uid honestly`() {
        fun elevWithUid(uid: Int) =
            ShizukuElevation(
                object : ShizukuBridge {
                    override val apiPresent = true

                    override fun pingBinder() = true

                    override fun hasPermission() = true

                    override fun newProcess(command: String): RawProcessResult? = null

                    override fun serverUid() = uid
                },
                Dispatchers.Unconfined,
            )
        // 2000 = adb shell (our preferred smaller surface), 0 = root, anything else = unknown.
        assertEquals(ShizukuPrivilege.ADB, elevWithUid(2000).serverPrivilege())
        assertEquals(ShizukuPrivilege.ROOT, elevWithUid(0).serverPrivilege())
        assertEquals(ShizukuPrivilege.UNKNOWN, elevWithUid(-1).serverPrivilege())
    }

    @Test
    fun `requestPermission delegates to the bridge and reports dispatch`() = runBlocking {
        var asked = -1
        val bridge =
            object : ShizukuBridge {
                override val apiPresent = true

                override fun pingBinder() = true

                override fun hasPermission() = false

                override fun newProcess(command: String): RawProcessResult? = null

                override fun requestPermission(requestCode: Int): Boolean {
                    asked = requestCode
                    return true
                }
            }
        val e = ShizukuElevation(bridge, Dispatchers.Unconfined)
        assertTrue(e.requestPermission())
        assertEquals(ShizukuElevation.REQUEST_CODE_ONE_TAP, asked)
    }

    @Test
    fun `exec reports not-alive when the binder dies mid-session`() = runBlocking {
        // A held channel can die after connect (the corpus linkToDeath teardown,
        // ServiceStarter.java:138-141) — exec must report an honest alive=false, not a spawn lie.
        var live = true
        val bridge =
            object : ShizukuBridge {
                override val apiPresent = true

                override fun pingBinder() = live

                override fun hasPermission() = true

                override fun newProcess(command: String) =
                    RawProcessResult(0, "${ShizukuSentinel.MARKER} 0\n")
            }
        val shell = ShizukuElevation(bridge, Dispatchers.Unconfined).connect().getOrThrow()
        assertTrue(shell.isAlive)
        live = false // binder died
        assertFalse(shell.isAlive)
        val res = shell.exec("settings get secure always_on_vpn_app")
        assertEquals(-1, res.exit)
        assertFalse(res.ok)
        assertTrue(res.stderr.contains("not alive"))
    }

    // ---- exec wires through the sentinel + spawns only what it is given ------

    @Test
    fun `exec sends the sentinel-wrapped command and parses the result`() = runBlocking {
        val cmd = "settings get secure always_on_vpn_app"
        val fake =
            FakeBridge(
                responder = {
                    RawProcessResult(
                        exit = 0,
                        output = "app.torta.yeah\n${ShizukuSentinel.MARKER} 0\n",
                    )
                }
            )
        val shell = ShizukuElevation(fake, Dispatchers.Unconfined).connect().getOrThrow()
        val res = shell.exec(cmd)

        assertEquals(1, fake.seenCommands.size)
        assertEquals(ShizukuSentinel.wrap(cmd), fake.seenCommands.single())
        assertTrue(res.ok)
        assertEquals("app.torta.yeah", res.stdout)
    }

    @Test
    fun `exec degrades honestly when the process cannot be spawned`() = runBlocking {
        val fake = FakeBridge(responder = { null })
        val shell = ShizukuElevation(fake, Dispatchers.Unconfined).connect().getOrThrow()
        val res = shell.exec("am get-standby-bucket app.torta.yeah")
        assertEquals(-1, res.exit)
        assertFalse(res.ok)
        assertTrue(res.stderr.contains("could not be spawned"))
    }

    @Test
    fun `exec never concatenates anything beyond the given command plus sentinel`() = runBlocking {
        // Security (P11 §5.3): no user input is woven in — only the constant op + the fixed
        // sentinel.
        val op = "cmd appops set app.torta.yeah RUN_ANY_IN_BACKGROUND allow"
        val fake = FakeBridge(responder = { RawProcessResult(0, "${ShizukuSentinel.MARKER} 0\n") })
        val shell = ShizukuElevation(fake, Dispatchers.Unconfined).connect().getOrThrow()
        shell.exec(op)
        val sent = fake.seenCommands.single()
        assertTrue("must contain exactly the op", sent.startsWith(op))
        assertEquals(
            "op + sentinel only, nothing else",
            "$op; echo \"${ShizukuSentinel.MARKER} \$?\"",
            sent,
        )
    }
}
