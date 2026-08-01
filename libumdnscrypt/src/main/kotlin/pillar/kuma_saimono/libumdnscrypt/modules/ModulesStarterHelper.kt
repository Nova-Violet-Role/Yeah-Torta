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

package pillar.kuma_saimono.libumdnscrypt.modules

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Handler
import android.widget.Toast
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.jrummyapps.android.shell.CommandResult
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.installer.ChmodCommand
import pillar.kuma_saimono.libumdnscrypt.installer.DNSCryptExtractCommand
import pillar.kuma_saimono.libumdnscrypt.patches.Patch
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.Constants.NUMBER_REGEX
import pillar.kuma_saimono.libumdnscrypt.utils.enums.ModuleName
import pillar.kuma_saimono.libumdnscrypt.utils.portchecker.PortChecker
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils
import pillar.kuma_saimono.libumdnscrypt.di.SharedPreferencesModule
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.DNSCRYPT_LISTEN_PORT
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.HTTP3_QUIC
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.IGNORE_SYSTEM_DNS
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.RESOLVER_NATIVE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.WARDEN_NATIVE_ENABLED
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.DNSCRYPT_RUN_FRAGMENT_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark.Companion.TOP_FRAGMENT_MARK
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService.Companion.COMMAND_RESULT
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import javax.inject.Inject
import javax.inject.Named

class ModulesStarterHelper(
    private val context: Context,
    private val handler: Handler
) {

    @Inject
    @field:Named(SharedPreferencesModule.DEFAULT_PREFERENCES_NAME)
    lateinit var defaultPreferences: Lazy<SharedPreferences>
    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>
    @Inject
    lateinit var pathVars: PathVars
    @Inject
    lateinit var portChecker: Lazy<PortChecker>

    private val appDataDir: String
    private val busyboxPath: String
    private val dnscryptPath: String
    private val dnscryptConfPath: String

    private val modulesStatus: ModulesStatus

    private val lock: Lock = ReentrantLock()

    init {
        App.instance.daggerComponent.inject(this)
        appDataDir = pathVars.appDataDir
        busyboxPath = pathVars.busyboxPath
        dnscryptPath = pathVars.dnsCryptPath
        dnscryptConfPath = pathVars.dnscryptConfPath
        this.modulesStatus = ModulesStatus.getInstance()
    }

    fun getDNSCryptStarterRunnable(): Runnable {
        return Runnable {
            //new experiment
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)

            // ★ STAGE 2 (2026-07-04): DNSCrypt IS the pure-Rust tunnel now. The Go dnscrypt-proxy
            // binary (libdnscrypt-proxy.so) is DELETED — there is NO separate process to exec. The
            // encrypted DNSCrypt datapath is carried by tunnel::TunnelController (started from
            // ServiceVPN.startNative when the VPN establishes). Exec'ing the deleted binary here
            // returned exit -4 ("Error DNSCrypt: -4"), which the failure cascade read as
            // "DNSCrypt dead" → STOP → it tore down the successfully-raised Rust tunnel 2.5s later.
            // So the "DNSCrypt module" simply reports STARTED: mark the run-fragment started, and
            // let the ModulesStateLoop see it RUNNING. The real resolution proof is query.log, fed
            // by the Rust resolver::resolve the tunnel loop calls. No binary, no ProcessStarter.

            // ★ GAP-1 CONFIG AUTO-INSTALL (2026-07-04, measured on the x86_64 AVD): the pure-Rust
            // resolver derives its server pool from `server_names ∩ public-resolvers.md`
            // (ResolverRuntime.deriveConfiguredUpstreams) and routes 0x81 relays from relays.md.
            // Those signed lists (+ dnscrypt-proxy.toml) ship inside assets/dnscrypt.zip but were
            // only ever extracted by the legacy Installer Activity, which no longer runs in the
            // de-Go flow — so on a FRESH install the dnscrypt-proxy dir was EMPTY and the resolver
            // fell to the hardcoded 2-stamp floor (dc-quad9,dc-fr). Extract-if-missing here,
            // idempotent (skips when the signed list is already present + non-empty), so the full
            // 579-server auto-pick + the relay routes are live on the very first START. Reuses the
            // exact ResetModuleHelper.extractModuleData pattern (extract → chmod the dir).
            try {
                val resolvers = java.io.File(pathVars.getDNSCryptPublicResolversPath())
                if (!resolvers.isFile || resolvers.length() == 0L) {
                    DNSCryptExtractCommand(context, appDataDir).execute()
                    ChmodCommand.dirChmod(appDataDir + "/app_data/dnscrypt-proxy", false)
                    logw("DNSCrypt config auto-extracted from assets/dnscrypt.zip "
                            + "(public-resolvers.md/relays.md/dnscrypt-proxy.toml) — the signed source "
                            + "lists are now live for the Rust pool derivation + 0x81 relay routing")
                }
            } catch (e: Exception) {
                loge("DNSCrypt config auto-extract failed (resolver will use the 2-stamp floor)", e)
            }

            sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, ModulesService.DNSCRYPT_KEYWORD, dnscryptPath)
            logw("DNSCrypt started — pure-Rust tunnel engine (no Go binary; the datapath is "
                    + "tunnel::TunnelController via ServiceVPN.startNative)")
            return@Runnable
            /*
            String dnsCmdString;
            final CommandResult shellResult;
            if (modulesStatus.isUseModulesWithRoot()) {

                List<String> lines = readDnsCryptConfiguration();

                List<String> newLines = new ArrayList<>(lines);

                checkDnsCryptPortsForBusyness(newLines);

                patchIgnoreSystemDnsFromPref(newLines);

                patchHttp3FromPref(newLines);

                patchForceTcpFromPref(newLines);

                patchLogRotation(newLines);

                // query.log re-admitted for RELEASE (Socio 2026-06-25): the data theft was the REMOVED
                // error-report email that shipped the user's query.log + traffic to the upstream author on a
                // WiFi/dnscrypt failure — NOT the local log itself. cache/query.log is local-only (0600,
                // never leaves the device) and carries the resolver/relay per query — the transparency that
                // lets the user verify DNSCrypt is encrypted + the Rotation Engine is switching servers.
                // So enable it always, not just in DEBUG (method name kept to avoid touching call refs).
                enableQueryLogForDebug(newLines);

                // #2 status fix (Socio 2026-06-25): repoint dnscrypt's log_file off the stale upstream
                // pan.alexander.libumdnscrypt prefix the Installer never rewrites, so the NOTICE readiness
                // markers (" OK "/"lowest initial latency") land where the app READS the log — else the
                // module resolves fine yet stays frozen on "DNSCrypt Starting" forever.
                fixDnsCryptLogFilePath(newLines);

                if (lines.size() != newLines.size() || !new HashSet<>(lines).containsAll(newLines)) {
                    saveDnsCryptConfiguration(newLines);
                }

                checkModulesConfigPatches(false);

                dnsCmdString = busyboxPath + "nohup " + dnscryptPath
                        + " -config " + appDataDir
                        + "/app_data/dnscrypt-proxy/dnscrypt-proxy.toml -pidfile " + appDataDir
                        + "/dnscrypt-proxy.pid >/dev/null 2>&1 &";
                String waitString = busyboxPath + "sleep 3";
                String checkIfModuleRunning = busyboxPath + "pgrep -l /libdnscrypt-proxy.so";

                applyResolverNativeFromPref();

                applyWardenNativeFromPref();

                shellResult = Shell.SU.run(dnsCmdString, waitString, checkIfModuleRunning);

                preferenceRepository.get().setBoolPreference("DNSCryptStartedWithRoot", true);

                if (shellResult.getStdout().contains(dnscryptPath)) {
                    sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, dnscryptPath);
                } else {
                    sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, "");
                }

            } else {

                List<String> lines = readDnsCryptConfiguration();

                List<String> newLines = new ArrayList<>(lines);

                checkDnsCryptPortsForBusyness(newLines);

                patchIgnoreSystemDnsFromPref(newLines);

                patchHttp3FromPref(newLines);

                patchForceTcpFromPref(newLines);

                patchLogRotation(newLines);

                // query.log re-admitted for RELEASE (Socio 2026-06-25): the data theft was the REMOVED
                // error-report email that shipped the user's query.log + traffic to the upstream author on a
                // WiFi/dnscrypt failure — NOT the local log itself. cache/query.log is local-only (0600,
                // never leaves the device) and carries the resolver/relay per query — the transparency that
                // lets the user verify DNSCrypt is encrypted + the Rotation Engine is switching servers.
                // So enable it always, not just in DEBUG (method name kept to avoid touching call refs).
                enableQueryLogForDebug(newLines);

                // #2 status fix (Socio 2026-06-25): repoint dnscrypt's log_file off the stale upstream
                // pan.alexander.libumdnscrypt prefix the Installer never rewrites, so the NOTICE readiness
                // markers (" OK "/"lowest initial latency") land where the app READS the log — else the
                // module resolves fine yet stays frozen on "DNSCrypt Starting" forever.
                fixDnsCryptLogFilePath(newLines);

                if (lines.size() != newLines.size() || !new HashSet<>(lines).containsAll(newLines)) {
                    saveDnsCryptConfiguration(newLines);
                }

                checkModulesConfigPatches(false);

                dnsCmdString = dnscryptPath + " -config " + appDataDir
                        + "/app_data/dnscrypt-proxy/dnscrypt-proxy.toml -pidfile " + appDataDir + "/dnscrypt-proxy.pid";
                preferenceRepository.get().setBoolPreference("DNSCryptStartedWithRoot", false);

                applyResolverNativeFromPref();

                applyWardenNativeFromPref();

                shellResult = new ProcessStarter(context.getApplicationInfo().nativeLibraryDir)
                        .startProcess(dnsCmdString);
            }

            if (!shellResult.isSuccessful()) {

                if (modulesStatus.getDnsCryptState() == RESTARTING) {
                    return;
                }

                if (modulesStatus.getDnsCryptState() != STOPPING && modulesStatus.getDnsCryptState() != STOPPED) {

                    if (pathVars.getAppVersion().startsWith("b") && handler != null) {
                        showErrorToast("DNSCrypt Module Fault:", shellResult);
                    }

                    checkModulesConfigPatches(true);

                    sendAskRestoreDefaults(context, ModuleName.DNSCRYPT_MODULE);
                }

                loge("Error DNSCrypt: "
                        + shellResult.exitCode + " ERR=" + shellResult.getStderr()
                        + " OUT=" + shellResult.getStdout());

                logNativeCrash();

                if (!getApp(context).isAppForeground()
                        && modulesStatus.getDnsCryptState() == RUNNING
                        && modulesStatus.isDnsCryptReady()) {
                    ModulesRestarter.restartDNSCrypt(context);
                    logw("Trying to restart DNSCrypt");
                } else {
                    modulesStatus.setDnsCryptState(STOPPED);

                    ModulesAux.makeModulesStateExtraLoop(context);

                    sendResultIntent(DNSCRYPT_RUN_FRAGMENT_MARK, DNSCRYPT_KEYWORD, "");
                }

            }

            Thread.currentThread().interrupt();
            */
        }
    }

    private fun readDnsCryptConfiguration(): List<String> {
        return FileManager.readTextFileSynchronous(context, dnscryptConfPath)
    }

    private fun checkDnsCryptPortsForBusyness(lines: MutableList<String>) {
        val port = pathVars.dnsCryptPort
        val checker = portChecker.get()

        if (port.matches(NUMBER_REGEX.toRegex()) && checker.isPortBusy(port)) {

            val freePort = checker.getFreePort(port)

            if (freePort == port) {
                return
            }

            for (i in lines.indices) {
                var line = lines[i]
                if (line.contains("listen_addresses") && line.contains(port)) {
                    line = line.replace(port, freePort)
                    lines[i] = line
                }
            }
            defaultPreferences.get().edit().putString(DNSCRYPT_LISTEN_PORT, freePort).apply()
        }
    }

    /**
     * START-TIME http3/DoH3 patch — the start-path mirror of the user-toggle patch in
     * PreferencesDNSFragment.java:469-474 (which only runs inside onPreferenceChange). Without this,
     * the {@code HTTP3_QUIC} pref (TortaeKeys.java:131 {@code "http3"}; default-true via
     * preferences_dnscrypt.xml http3 CheckBoxPreference) never reaches the running TOML unless the
     * user manually toggles the switch. The read uses {@code getBoolean(HTTP3_QUIC, true)} — a
     * default of {@code true} that MATCHES the preferences_dnscrypt.xml CheckBoxPreference default —
     * so DoH3 fires RELIABLY on the FIRST start even on a not-yet-materialized pref (a headless
     * boot-start before the UI ran {@code setDefaultValues(preferences_dnscrypt)} @ TopFragment:603),
     * not "on auto-heal/next-start only." Same shape/cadence as {@link #checkDnsCryptPortsForBusyness} and
     * {@link #enableQueryLogForDebug}: a void method mutating {@code newLines} by reference, run at
     * dnscrypt START only (never at preset-time / no live-arm), guarded by the size/diff save-check
     * at the call site so an added/removed line triggers saveDnsCryptConfiguration.
     * <p>
     * The raw-line form mirrors PreferencesDNSFragment's reconstruction ({@code key + " = " + val} →
     * {@code "http3 = true"}, inserted on the line immediately after the {@code ignore_system_dns}
     * line, PreferencesDNSFragment.java:470-473).
     * <p>
     * <b>Idempotent + fail-safe.</b> If pref TRUE and no http3 line exists, insert {@code http3 = true}
     * after the {@code ignore_system_dns} line; on the next ~10s state-loop pass the http3 scan finds
     * that line and no-ops (same re-entry guarantee as {@link #enableQueryLogForDebug}). If pref FALSE
     * and an http3 line exists, comment it ({@code #http3 ...}) — honoring the pref without deleting
     * the user's line. If {@code ignore_system_dns} is absent (e.g. a non-standard TOML), it no-ops —
     * the dnscrypt start path is never broken.
     */
    private fun patchHttp3FromPref(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }

        val http3Enabled = defaultPreferences.get().getBoolean(HTTP3_QUIC, true)

        var ignoreSystemDnsIndex = -1
        var http3Index = -1
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            // Strip a single leading '#' so a commented http3 line is detected too (comment-agnostic).
            val bare = if (trimmed.startsWith("#")) trimmed.substring(1).trim() else trimmed
            if (bare.startsWith("ignore_system_dns")) {
                ignoreSystemDnsIndex = i
            }
            if (bare.startsWith("http3")) {
                http3Index = i
            }
        }

        if (http3Enabled) {
            // Insert "http3 = true" right after the ignore_system_dns line — raw-line equivalent of
            // PreferencesDNSFragment.java:471-473. No-op if a (commented or live) http3 line is already
            // present, or if ignore_system_dns is absent (fail-safe, start path untouched).
            if (http3Index < 0 && ignoreSystemDnsIndex >= 0) {
                lines.add(ignoreSystemDnsIndex + 1, "http3 = true")
            } else if (http3Index >= 0) {
                // An http3 line exists: ensure it is uncommented + true so the pref is honored.
                val enabledLine = "http3 = true"
                if (lines[http3Index] != enabledLine) {
                    lines[http3Index] = enabledLine
                }
            }
        } else {
            // Pref OFF: comment any live http3 line (never delete — keep it as the user's row).
            if (http3Index >= 0) {
                val existing = lines[http3Index].trim()
                if (!existing.startsWith("#")) {
                    lines[http3Index] = "#" + existing
                }
            }
        }
    }

    /**
     * START-TIME log-rotation patch (Socio 2026-06-25) — BOUND query.log + DnsCrypt.log so the Rotation
     * Engine's per-cycle appends (every ~5 min) + the live query stream can NEVER grow the on-NAND files
     * unbounded, and they self-clean regularly. The SAFE mechanism: dnscrypt-proxy rotates its OWN files
     * (it holds both handles — an app-side head-truncate would corrupt its append offset). Setting the
     * dnscrypt-proxy global lumberjack knobs ({@code log_files_max_size} MB / {@code _max_age} days /
     * {@code _max_backups}) applies to BOTH the {@code log_file} and the {@code [query_log] file}. SET-ONLY
     * + idempotent (pins the bound at every start, sibling cadence to {@link #patchHttp3FromPref}); never
     * throws into the start path. 2 MB holds thousands of recent entries — the transparency window the user
     * reads stays intact, just bounded.
     */
    private fun patchLogRotation(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }
        setOrAddTopLevelToml(lines, "log_files_max_size", "2")     // MB cap → rotate (the anti-bloat bound)
        setOrAddTopLevelToml(lines, "log_files_max_age", "7")      // days backstop
        setOrAddTopLevelToml(lines, "log_files_max_backups", "1")  // keep 1 rotated backup (bounded total)
    }

    /**
     * Set a TOP-LEVEL {@code key = value} TOML line, comment-agnostic: replace a live/commented existing
     * line, else insert it BEFORE the first {@code [section]} header (so a top-level key never lands inside
     * a section). Mirrors the {@link #patchHttp3FromPref} set-only discipline; fail-safe (no-op on null).
     */
    private fun setOrAddTopLevelToml(lines: MutableList<String>, key: String, value: String) {
        val target = key + " = " + value
        var idx = -1
        var firstSection = -1
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            if (firstSection < 0 && trimmed.startsWith("[")) {
                firstSection = i
            }
            val bare = if (trimmed.startsWith("#")) trimmed.substring(1).trim() else trimmed
            if (bare.startsWith(key)) {
                idx = i
                break
            }
        }
        if (idx >= 0) {
            if (lines[idx] != target) {
                lines[idx] = target
            }
        } else if (firstSection >= 0) {
            lines.add(firstSection, target)
        } else {
            lines.add(target)
        }
    }

    /**
     * START-TIME force_tcp patch (Socio 2026-06-25) — the legacy "Always use TCP" option (force_tcp) was a
     * TOR-ONLY setting (DNSCrypt-over-Tor needs TCP because Tor carries no UDP). Tortä has NO Tor, and
     * forcing TCP starves the YeAH UDP transport — dnscrypt-proxy encrypts everything over UDP anyway, so
     * TCP-only only adds latency AND clashes with our TCP/UDP YeAH engine. The pref now defaults OFF; this
     * pins the live TOML to the pref at every start (SET-ONLY, like {@link #patchHttp3FromPref}) so a
     * stale/shipped — OR stale persisted-true — {@code force_tcp = true} can never silently force TCP
     * behind the engine's back. UNCONDITIONAL: no Tor means force_tcp has no legitimate use in Tortä, so
     * it is pinned OFF regardless of the (legacy) toggle — honoring a stale persisted "true" would just
     * re-break the YeAH UDP path.
     */
    private fun patchForceTcpFromPref(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }
        val target = "force_tcp = false"
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            val bare = if (trimmed.startsWith("#")) trimmed.substring(1).trim() else trimmed
            if (bare.startsWith("force_tcp")) {
                if (target != lines[i]) {
                    lines[i] = target
                }
                return
            }
        }
    }

    /**
     * START-TIME ignore_system_dns PRIVACY patch — sibling of {@link #patchHttp3FromPref}, but
     * SET-ONLY (never insert/remove). The {@code ignore_system_dns} pref
     * (TortaeKeys.java:129 {@code "ignore_system_dns"}; default-true via the
     * preferences_dnscrypt.xml CheckBoxPreference) means: when {@code true}, DNSCrypt does NOT use
     * system DNS settings at bootstrap and unconditionally uses the {@code bootstrap_resolvers}
     * (default {@code 9.9.9.9}, Quad9 — reachable) → no bootstrap leak to ISP/system DNS. That is the
     * privacy posture, so the read defaults to {@code true}. USER-FREEDOM: if the user turns the pref
     * OFF, we faithfully write {@code ignore_system_dns = false}.
     * <p>
     * The shipped dnscrypt-proxy.toml always carries an {@code ignore_system_dns} line (it is the
     * http3 insert-anchor, PreferencesDNSFragment.java:470), so this method only ever SETS the
     * existing line's value to the canonical {@code ignore_system_dns = <bool>} form — comment-agnostic
     * (strips a single leading '#' for detection, then writes the uncommented canonical line). It never
     * adds or removes a line, so the list size is unchanged; the value flip persists via the call
     * site's {@code !containsAll} save-guard ({@link #getDNSCryptStarterRunnable}, :134/:171). If the
     * line is absent (a non-standard TOML), it no-ops — the dnscrypt start path is never broken.
     * <p>
     * Wired BEFORE {@link #patchHttp3FromPref} in both start branches so ignore_system_dns is set
     * first; http3 still anchors its insert on the same {@code ignore_system_dns} line.
     */
    private fun patchIgnoreSystemDnsFromPref(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }

        val ignoreSystemDns = defaultPreferences.get().getBoolean(IGNORE_SYSTEM_DNS, true)

        var ignoreSystemDnsIndex = -1
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            // Strip a single leading '#' so a commented ignore_system_dns line is detected too.
            val bare = if (trimmed.startsWith("#")) trimmed.substring(1).trim() else trimmed
            if (bare.startsWith("ignore_system_dns")) {
                ignoreSystemDnsIndex = i
                break
            }
        }

        // SET-ONLY: write the canonical uncommented line honoring the pref (privacy-default true,
        // user-freedom false). No-op (start path untouched) if the line is absent.
        if (ignoreSystemDnsIndex >= 0) {
            val canonicalLine = "ignore_system_dns = " + (if (ignoreSystemDns) "true" else "false")
            if (lines[ignoreSystemDnsIndex] != canonicalLine) {
                lines[ignoreSystemDnsIndex] = canonicalLine
            }
        }
    }

    /**
     * START-TIME native-resolver datapath ARM — P7 Wave 3 Stage-1. Unlike {@link #patchHttp3FromPref} /
     * {@link #patchIgnoreSystemDnsFromPref} (which mutate the dnscrypt TOML by reference), this pushes the
     * {@code RESOLVER_NATIVE_ENABLED} pref straight to the C tunnel's atomic flag — a DIFFERENT kind of apply
     * (a .so call, not a TOML line), so it runs OUTSIDE the TOML save-guard, right before each DNSCrypt
     * process launch in BOTH the root and no-root branches (sibling cadence to the patch helpers).
     * <p>
     * It targets {@link pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils#setResolverNativeEnabled(boolean)} — the crash-safe face over the C native
     * {@code jni_set_resolver_native} that lives in {@code libinvizible.so} (the SAME library {@code udp.c}
     * reads {@code g_resolver_native_enabled} from). It deliberately is NOT the {@code TortaCore} face:
     * {@code TortaCore} loads {@code libtorta_core.so}, a SEPARATE library that does not host this flag, so a
     * {@code TortaCore} call would never reach {@code udp.c}'s flag (an {@link UnsatisfiedLinkError} swallowed
     * into a silent no-op — the arm-wire would be dead).
     * <p>
     * The read uses {@code getBoolean(RESOLVER_NATIVE_ENABLED, false)} — default {@code false}
     * (TortaeKeys.java:165), so on a fresh / not-yet-materialized pref the setter receives {@code false},
     * the C {@code g_resolver_native_enabled} stays 0, the udp.c gate short-circuits, and the datapath is
     * BYTE-IDENTICAL to today (no behavior change). Only an explicit user/#85 arm flips the pref to true.
     * <p>
     * <b>Fail-safe + crash-safe.</b> {@link pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils#setResolverNativeEnabled(boolean)} is itself crash-proof
     * (a missing {@code .so} / UnsatisfiedLinkError / native fault no-ops, the flag stays 0 = disarmed), and
     * the C bridge is fail-safe (a {@code torta_resolve} result ≤ 0 falls through to the unchanged sendto, so
     * DNS never breaks). The DNSCrypt start path is never affected by this call's outcome.
     */
    private fun applyResolverNativeFromPref() {
        val enabled = defaultPreferences.get().getBoolean(RESOLVER_NATIVE_ENABLED, true)
        // E-FIX round-1: the setter now ensure-loads libinvizible.so itself (no more dependence on the
        // ServiceVPN class-load order) and reports whether the push reached the C layer — log the truth
        // instead of silently claiming an arm that never landed (the round-1 cold-start false-positive).
        val landed = VpnUtils.setResolverNativeEnabled(enabled)
        if (!landed) {
            logw("ModulesStarterHelper — resolver native arm push did NOT land"
                    + " (libinvizible unavailable); C seam flag stays 0, datapath stays dnscrypt")
        }
    }

    /**
     * START-TIME native-Warden (firewall verdict) datapath ARM — THE WARDEN W3. The exact structural mirror
     * of {@link #applyResolverNativeFromPref()}: it pushes the {@code WARDEN_NATIVE_ENABLED} pref straight to
     * the C tunnel's atomic flag (a {@code .so} call, not a TOML line), so it runs OUTSIDE the TOML save-guard,
     * right before each DNSCrypt process launch in BOTH the root and no-root branches (sibling cadence to
     * {@link #applyResolverNativeFromPref()} and the patch helpers).
     * <p>
     * It targets {@link pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils#setWardenNativeEnabled(boolean)} — the
     * crash-safe face over the C native {@code jni_set_warden_native} that lives in {@code libinvizible.so}
     * (the SAME library {@code ip.c}/{@code session.c} read {@code g_warden_native_enabled} from). It is NOT
     * the {@code TortaCore} face: {@code TortaCore} loads {@code libtorta_core.so}, a SEPARATE library that
     * does not host this flag, so a {@code TortaCore} call would never reach the C gate.
     * <p>
     * <b>DEFAULT OFF</b> — read as {@code getBoolean(WARDEN_NATIVE_ENABLED, true)} (the Socio default-ON
     * contract 2026-06-24; the same default-ON shape as {@link #applyResolverNativeFromPref()}). On a fresh /
     * not-yet-materialized pref the setter receives {@code true}, the C {@code g_warden_native_enabled} is
     * armed to 1, and the ip.c/session.c seams call into the Rust verdict bridge. This is SAFE-by-construction:
     * arming alone NEVER enforces — the Rust Warden global ships UNCONFIGURED (None ⇒ ABSTAIN), so until the
     * W4 policy brain feeds it a signed policy every verdict is ABSTAIN and the datapath is byte-identical (no
     * spurious block). Reversible — the user can flip the {@code pref_warden_native} switch OFF (USER FREEDOM),
     * which makes this read {@code false} → the setter disarms the C flag → byte-identical short-circuit.
     * <p>
     * <b>Fail-safe + crash-safe.</b> {@link pillar.kuma_saimono.libumdnscrypt.vpn.VpnUtils#setWardenNativeEnabled(boolean)}
     * is itself crash-proof (a missing {@code .so} / UnsatisfiedLinkError / native fault no-ops, the flag stays
     * 0 = disarmed), and the C bridge is fail-safe (a verdict ≤ 0 / ABSTAIN falls through to the existing
     * is_address_allowed path, additive-block-only). The DNSCrypt start path is never affected by the outcome.
     */
    private fun applyWardenNativeFromPref() {
        val enabled = defaultPreferences.get().getBoolean(WARDEN_NATIVE_ENABLED, false)
        // E-FIX round-1: mirror of applyResolverNativeFromPref — honest landed-state logging.
        val landed = VpnUtils.setWardenNativeEnabled(enabled)
        if (!landed) {
            logw("ModulesStarterHelper — Warden native arm push did NOT land"
                    + " (libinvizible unavailable); C seam flag stays 0, verdict seam stays dormant")
        }
    }

    private fun saveDnsCryptConfiguration(lines: List<String>) {
        FileManager.writeTextFileSynchronous(context, dnscryptConfPath, lines)
    }

    /**
     * DEBUG-ONLY (BuildConfig.DEBUG). Enables the dnscrypt-proxy [query_log] sink so the app's
     * Wave-3 shadow gets a LIVE qname trigger in DNSCrypt-VPN mode (see QueryLogTailer +
     * ResolverRuntime.shadowCompare). Release NEVER calls this, so a privacy DNS app ships query
     * logging OFF and writes no query.log.
     * <p>
     * The shipped template line is commented and carries the stale upstream prefix
     * ({@code #file = '/data/user/0/pan.alexander.libumdnscrypt/cache/query.log'}); the install-time
     * rewrite in Installer only touches {@code pillar.kuma_saimono.*} lines, so this one is never
     * fixed. We therefore locate the line by its {@code cache/query.log} SUFFIX (never by prefix)
     * and replace the whole value with the real, absolute, uncommented appDataDir path — the SAME
     * string QueryLogTailer reads ({@code PathVars.getAppDataDir() + "/cache/query.log"},
     * QueryLogTailer.kt:94). The nx_log line (cache/nx.log) and ignored_qtypes/format are untouched.
     * <p>
     * <b>APPEND FALLBACK (Wave-3 qname-producer guarantee).</b> The scan above is REPLACE-ONLY: if
     * this fork's dnscrypt-proxy.toml blob (shipped inside assets/dnscrypt.zip — no plain-text
     * {@code query_log} match exists in src/main/assets) lacks any {@code cache/query.log}-suffixed
     * {@code file =} line, the old version silently wrote nothing, dnscrypt-proxy produced no
     * query.log, the tailer no-op'd, the qname counters stayed 0, and the soak looked "green/quiet"
     * while testing nothing (the exact failure recorded in shadow-seam-unreachable-dnscrypt-mode.md:
     * ready=2, 130+ resolutions, ZERO compares). To GUARANTEE the producer we now, when no file-line
     * was found+rewritten, either insert the absolute {@code file =} line under a pre-existing
     * {@code [query_log]} header (avoiding a duplicate-table TOML parse error) or, failing that,
     * append a complete self-contained {@code [query_log]} block (absolute appDataDir path) at EOF.
     * <p>
     * <b>Idempotent.</b> Re-running never double-appends: the very {@code file =} line we add/insert
     * is itself matched by the suffix scan on the next call, hits the {@code line.equals(targetLine)}
     * no-op branch, and returns before any append. (The state loop re-enters every ~10s, so this MUST
     * stay re-entry-safe.) DEBUG-only; release never calls this, so a privacy DNS app writes no query.log.
     */
    private fun enableQueryLogForDebug(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }
        val targetLine = "file = '" + appDataDir + "/cache/query.log'"
        var queryLogHeaderIndex = -1
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            // Match the [query_log] file line by suffix only (comment state + stale prefix agnostic).
            // Exclude the nx_log line, whose value ends in cache/nx.log.
            if (trimmed.endsWith("cache/query.log'") || trimmed.endsWith("cache/query.log\"")) {
                if (line != targetLine) {
                    lines[i] = targetLine
                }
                // Found + (re)wrote the producer line — idempotent guarantee complete, no append.
                return
            }
            // Remember a pre-existing [query_log] section header (comment-agnostic) so the fallback can
            // insert the file= line UNDER it rather than declaring a duplicate table (a TOML parse error
            // in dnscrypt-proxy's Go toml). Strip a leading '#' before matching the bare header form.
            val header = if (trimmed.startsWith("#")) trimmed.substring(1).trim() else trimmed
            if (header == "[query_log]" && queryLogHeaderIndex < 0) {
                queryLogHeaderIndex = i
            }
        }

        // No cache/query.log file-line existed to rewrite — GUARANTEE the producer (append fallback).
        if (queryLogHeaderIndex >= 0) {
            // A [query_log] section header is present but its file= line is missing/renamed: ensure the
            // header itself is uncommented, then insert the absolute file= line directly under it.
            val headerLine = lines[queryLogHeaderIndex].trim()
            if (headerLine != "[query_log]") {
                lines[queryLogHeaderIndex] = "[query_log]"
            }
            // Insert the file= line EXACTLY as targetLine (no indent) so the suffix scan's
            // line.equals(targetLine) no-op branch fires on the very next call — single-pass idempotent.
            lines.add(queryLogHeaderIndex + 1, targetLine)
        } else {
            // No [query_log] table at all in this blob: append a complete, self-contained one at EOF.
            // The file= line is targetLine verbatim (no indent) for the same single-pass idempotency.
            lines.add("")
            lines.add("[query_log]")
            lines.add(targetLine)
        }
    }

    /**
     * #2 status fix — repoint dnscrypt-proxy's {@code log_file} to the SAME path the app reads
     * ({@code appDataDir + "/logs/DnsCrypt.log"}, ModulesLogRepositoryImpl.kt:60). The shipped blob carries
     * the stale upstream prefix ({@code log_file = '/data/user/0/pan.alexander.libumdnscrypt/logs/DnsCrypt.log'})
     * which the install-time rewrite never fixes (it only touches the fork's own package lines), so
     * dnscrypt-proxy writes its NOTICE log — including the {@code " OK "} resolver list and the
     * {@code "lowest initial latency"} line that {@link pillar.kuma_saimono.libumdnscrypt.domain.log_reader.dnscrypt.DNSCryptLogParser}
     * keys "started successfully" on — to a path this fork's uid can neither write nor read. The result:
     * the module resolves perfectly (query.log fills) yet {@code isDnsCryptReady} never flips, so the
     * dashboard is frozen on "DNSCrypt Starting" indefinitely.
     * <p>
     * Located by the {@code logs/DnsCrypt.log} SUFFIX (stale-prefix + comment-state agnostic, exactly like
     * {@link #enableQueryLogForDebug}); the whole value is replaced with the absolute, uncommented appDataDir
     * path. <b>Idempotent</b>: the line we write is matched by this same scan on the next ~10s re-entry and
     * hits the {@code line.equals(targetLine)} no-op. Runs in RELEASE too — readiness/status is not a debug
     * concern. (dnscrypt-proxy runs as the app uid, so {@code appDataDir/logs} is writable; the app already
     * keeps a DnsCrypt.log there.)
     */
    private fun fixDnsCryptLogFilePath(lines: MutableList<String>?) {
        if (lines == null) {
            return
        }
        val targetLine = "log_file = '" + appDataDir + "/logs/DnsCrypt.log'"
        for (i in lines.indices) {
            val line = lines[i]
            val trimmed = line.trim()
            if (trimmed.contains("log_file")
                    && (trimmed.endsWith("logs/DnsCrypt.log'") || trimmed.endsWith("logs/DnsCrypt.log\""))) {
                if (line != targetLine) {
                    lines[i] = targetLine
                }
                return
            }
        }
    }

    private fun sendResultIntent(moduleMark: Int, moduleKeyWord: String, binaryPath: String) {
        val comResult = RootCommands(arrayListOf(moduleKeyWord, binaryPath))
        val intent = Intent(COMMAND_RESULT)
        intent.putExtra("CommandsResult", comResult)
        intent.putExtra("Mark", moduleMark)
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
    }

    private fun sendAskRestoreDefaults(context: Context, module: ModuleName) {
        val intent = Intent(ASK_RESTORE_DEFAULTS)
        intent.putExtra("Mark", TOP_FRAGMENT_MARK)
        intent.putExtra(MODULE_NAME, module)
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
    }

    private fun checkModulesConfigPatches(forceCheck: Boolean) {
        if (lock.tryLock()) {
            try {
                val patch = Patch(context, pathVars)
                patch.checkPatches(forceCheck)
            } catch (e: Exception) {
                loge("ModulesStarterHelper checkModulesConfigPatches", e)
            } finally {
                lock.unlock()
            }
        }
    }

    private fun showErrorToast(prefix: String, shellResult: CommandResult) {
        val builder = StringBuilder(prefix)
        builder.append(" ").append(shellResult.exitCode)
        if (!shellResult.getStderr().isEmpty()) {
            builder.append("\n\n ERR: ").append(shellResult.getStderr())
        }
        if (!shellResult.getStdout().isEmpty()) {
            builder.append("\n\n OUT: ").append(shellResult.getStdout())
        }
        handler.post { Toast.makeText(context, builder.toString(), Toast.LENGTH_LONG).show() }
    }

    private fun logNativeCrash() {
        try {
            val sdf = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.getDefault())
            val time = sdf.format(Date(System.currentTimeMillis() - 3000))
            val process = ProcessBuilder(
                "logcat",
                "-d",
                "*:F",
                "-t",
                time
            ).start()
            InputStreamReader(process.inputStream).use { isr ->
                BufferedReader(isr).use { br ->
                    var line = br.readLine()
                    while (line != null) {
                        loge(line)
                        line = br.readLine()
                    }
                }
            }
        } catch (e: Exception) {
            loge("ModulesStarterHelper logNativeCrash", e)
        }
    }

    companion object {
        const val ASK_RESTORE_DEFAULTS = "pillar.kuma_saimono.libumdnscrypt.AskRestoreDefaults"
        const val MODULE_NAME = "pillar.kuma_saimono.libumdnscrypt.ModuleName"
    }

}
