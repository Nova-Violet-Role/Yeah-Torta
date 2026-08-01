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

import android.content.Context
import androidx.preference.PreferenceManager
import pillar.kuma_saimono.libumdnscrypt.BuildConfig
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys
import uniffi.torta_core.InuBootDurability
import uniffi.torta_core.InuPowerFlag
import uniffi.torta_core.InuPowerId
import uniffi.torta_core.InuStore

/**
 * The [PowerStateStore] backed by the Rust RAM⊗NAND [InuStore] (via UniFFI) — the replacement for
 * the retired `SharedPreferencesPowerStateStore`. The per-power `{id →
 * {desired,lastVerified,lastResult}}` map now lives inside the typed [uniffi.torta_core.InuState]
 * record persisted through the Rust `DurableTier` (atomic tmp+rename NAND + a RAM tier), NOT
 * SharedPreferences — so the Inu pillar keeps ZERO SharedPreferences for its power state.
 *
 * ## One source of truth across BOTH pillars (F17)
 * Both grant entry points — the notification/wizard grant ([WireCakeInuManager]) AND the Expert
 * keep-alive card ([pillar.kuma_saimono.libumdnscrypt.dns_engine.keepalive.BatteryKeepAliveCardView]) —
 * receive the SAME scoped [InuStore] handle from the `WireCakeInuComponent`, so the persisted power
 * map is one shared record. (The old code shared the SharedPreferences key; the shared handle is
 * the stronger equivalent.)
 *
 * ## Read-modify-write preserves the non-power fields
 * [save] rehydrates the current [uniffi.torta_core.InuState] first, then replaces ONLY `powers`
 * (via `copy`), so the pair flag / grantedAt / expert toggle / provider / status the record also
 * carries are never clobbered by a power-map write. `fully_protected` is DERIVED by Rust on persist
 * (a caller value is ignored). Fail-closed: any FFI error loads as "nothing held" (never a fake
 * "protected").
 */
class RustPowerStateStore(private val store: InuStore) : PowerStateStore {

    override fun load(): List<PowerState> =
        try {
            store.rehydrate().powers.mapNotNull { it.toPowerState() }
        } catch (e: Throwable) {
            loge("RustPowerStateStore load", e)
            emptyList()
        }

    override fun save(states: List<PowerState>) {
        try {
            val current = store.rehydrate()
            val next = current.copy(powers = states.mapNotNull { it.toInuPowerFlag() })
            store.persist(next)
        } catch (e: Throwable) {
            loge("RustPowerStateStore save", e)
        }
    }
}

/**
 * The set of powers the [PowerCatalogue] flags drift-prone (re-applied on boot). Used to
 * denormalize the [InuBootDurability] tag onto each [InuPowerFlag] as it is written (the
 * authoritative source stays the catalogue). Pure — `build` needs no Android and no UID for the
 * drift-prone subset.
 */
internal val INU_DRIFT_PRONE_IDS: Set<PowerId> by lazy {
    try {
        PowerCatalogue.build(BuildConfig.APPLICATION_ID)
            .filter { it.driftProne }
            .map { it.id }
            .toSet()
    } catch (e: Throwable) {
        loge("INU_DRIFT_PRONE_IDS", e)
        emptySet()
    }
}

/**
 * [PowerId] ⇄ [InuPowerId] by enum NAME — the two enums are hand-authored to have identical names
 * (`ALWAYS_ON_VPN` … `WRITE_SECURE_SETTINGS`), which is the cross-store-compat contract. Null-safe:
 * an unknown name (never, in practice) is skipped rather than throwing.
 */
internal fun PowerId.toInuPowerId(): InuPowerId? = runCatching {
    InuPowerId.valueOf(name)
}
    .getOrNull()

internal fun InuPowerId.toPowerId(): PowerId? = runCatching { PowerId.valueOf(name) }.getOrNull()

/**
 * Map a Kotlin [PowerState] to the typed [InuPowerFlag], stamping the boot-durability from the
 * catalogue.
 */
internal fun PowerState.toInuPowerFlag(): InuPowerFlag? {
    val inuId = id.toInuPowerId() ?: return null
    return InuPowerFlag(
        id = inuId,
        desired = desired,
        lastVerified = lastVerified,
        lastResult = lastResult,
        durability =
            if (id in INU_DRIFT_PRONE_IDS) InuBootDurability.DRIFT_PRONE
            else InuBootDurability.DURABLE,
    )
}

/**
 * Map a typed [InuPowerFlag] back to the Kotlin [PowerState] (drops the durability tag — not in
 * PowerState).
 */
internal fun InuPowerFlag.toPowerState(): PowerState? {
    val powerId = id.toPowerId() ?: return null
    return PowerState(
        id = powerId,
        desired = desired,
        lastVerified = lastVerified,
        lastResult = lastResult,
    )
}

/**
 * The ONE-TIME back-compat migration (F9/F10): fold the four legacy `WIRELESS_DEBUG_*`
 * SharedPreferences keys into the Rust [uniffi.torta_core.InuState] the first time the durable
 * record is cold. Without this, a user who already granted the no-root powers would keep them
 * ENFORCED on-device while the app reads "nothing held" — losing the revert path.
 *
 * This is the ONLY SharedPreferences READ left in the pillar and it is transitional (a read of the
 * OLD keys, never an ongoing store). It runs once, inside the KI-scoped [InuStore] provider, so it
 * fires exactly once per process at first component access.
 */
object LegacyInuMigration {

    /**
     * Open the durable [InuStore] rooted at `filesDir` and seed it from the legacy prefs if it is
     * cold.
     */
    fun openAndMigrate(context: Context): InuStore {
        val app = context.applicationContext
        val store = InuStore(app.filesDir.absolutePath)
        try {
            val current = store.rehydrate()
            // Only seed when the durable record has nothing yet (no powers, never paired) — never
            // clobber
            // a record the Rust tier already owns.
            if (current.powers.isEmpty() && !current.paired) {
                val prefs = PreferenceManager.getDefaultSharedPreferences(app)
                val legacyMap = prefs.getString(TortaeKeys.WIRELESS_DEBUG_POWER_MAP, null)
                val legacyGranted = prefs.getBoolean(TortaeKeys.WIRELESS_DEBUG_GRANTED, false)
                val legacyGrantedAt = prefs.getLong(TortaeKeys.WIRELESS_DEBUG_GRANTED_AT, 0L)
                if (!legacyMap.isNullOrBlank() || legacyGranted) {
                    val powers =
                        PowerStateCodec.decode(legacyMap).mapNotNull { it.toInuPowerFlag() }
                    store.persist(
                        current.copy(
                            paired = legacyGranted,
                            grantedAt = legacyGrantedAt,
                            powers = powers,
                        )
                    )
                }
            }
            // #21 G7-RESIDUAL: fold the legacy boot-reapply pref into the record's hdr bit2
            // (InuState.bootReapply). UNLIKE the cold-guard block above, this must run even on a
            // WARM record — a pre-#21 install has a live powers record AND the armed pref side by
            // side. One-shot by key REMOVAL after a successful durable write (the fold latch);
            // afterwards every read/write rides the typed store (TortaPillarBridge + the boot
            // receiver), never this key.
            val prefs = PreferenceManager.getDefaultSharedPreferences(app)
            if (prefs.contains(TortaeKeys.INU_BOOT_REAPPLY)) {
                val armed = prefs.getBoolean(TortaeKeys.INU_BOOT_REAPPLY, false)
                val folded = if (armed && !store.bootReapply()) {
                    store.setBootReapply(true)
                } else {
                    true // disarmed/absent value or already-folded record — nothing to carry.
                }
                if (folded) {
                    prefs.edit().remove(TortaeKeys.INU_BOOT_REAPPLY).apply()
                }
            }
        } catch (e: Throwable) {
            loge("LegacyInuMigration.openAndMigrate", e)
        }
        return store
    }
}
