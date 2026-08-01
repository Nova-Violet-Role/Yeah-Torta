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

package pillar.kuma_saimono.libumdnscrypt.about

import android.media.AudioManager
import android.media.ToneGenerator
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge

/**
 * #96c Truth Terminal · the audio cue for each /slash egg + the reverse-crawl theme.
 *
 * Fire-and-forget, ToneGenerator-only (no asset, no MediaPlayer/SoundPool, no synthesis).
 * Each egg plays its OWN DISTINCT short original chiptune motif (the AUDIO LAW: one distinct
 * cue per egg) of DTMF tones over [AudioManager.STREAM_MUSIC] (so it respects the system music
 * volume + mute — silent if the user has muted music). Every motif is an ORIGINAL arrangement
 * of synthesized telephony tones — homage only, NEVER a sampled/licensed/copyrighted track.
 *
 * Leak-safe by construction: ONE [ToneGenerator] is built per cue, used on a single
 * throwaway worker thread, and released in a `finally` — nothing is retained, there is no
 * [android.os.Handler]/posted callback to leak, and the `object` captures no Context. This
 * mirrors the #96a no-leak discipline (timestamp/local math only, every path try/catch + loge,
 * fail-open). [ToneGenerator] needs no audio permission and no manifest change.
 *
 * Swap-point for the TIER-D future: when the real chiptune `.ogg` assets land, the body of
 * [playSequence] is the single seam that changes — the [Egg] enum and the `playCue(Egg)`
 * signature stay identical, so [EggConsoleSheet] and AboutActivity callers are untouched.
 */
enum class Egg {
    SATOSHI, CONRAD, JOE, GNUTELLA,   // the named /slash eggs
    TRUTH, YEAH, HELP,                // the visible spice eggs
    EMINEM, EINSTEIN,                 // hidden deep-cuts (not in the visible suggestion chips)
    CREDITS_THEME                     // the reverse-crawl march (NOT a /slash egg — see [playReverseTheme])
}

object EggAudio {

    private const val VOLUME = 70            // 0..100 (ToneGenerator.MAX_VOLUME == 100); SPEC ~70
    private const val NOTE_MS = 140          // each note's auto-stop duration
    private const val GAP_MS = 60L           // silence between notes
    private const val THEME_LOOP_GAP_MS = 500L // rest between forward-march loops (reads as a march)

    // ── AUDIO LAW: one DISTINCT original chiptune motif per egg (Nintendo/Konami-mono,
    //    NEVER a real copyrighted track — homage only). Every value is a real, stable
    //    android.media.ToneGenerator DTMF constant; the MOTIF (shape + register) is original.
    //    Distinct by SHAPE (rise / heroic-leap / gentle-descent / driving-low / two-note reveal /
    //    up-blip / flat-double / staccato-triple / zig-zag) AND by register band.

    // /Satoshi — the cryptic RISE (White-Rabbit ascent), refined +1 step from the #96b motif.
    private val SATOSHI_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_3, ToneGenerator.TONE_DTMF_6,
        ToneGenerator.TONE_DTMF_9, ToneGenerator.TONE_DTMF_C
    )
    // /Conrad — TV-series-theme-FLAVORED original (Black Angel homage): a heroic sting that
    //    leaps then resolves (up-up-down-up), evoking a title theme without copying one.
    private val CONRAD_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_5, ToneGenerator.TONE_DTMF_9,
        ToneGenerator.TONE_DTMF_6, ToneGenerator.TONE_DTMF_C
    )
    // /Joe — Lavender-Town-GENTLE, de-creeped: a soft nostalgic descent-with-lift (wistful,
    //    not horror). Re-homes the old GEOVY mood.
    private val JOE_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_8, ToneGenerator.TONE_DTMF_6,
        ToneGenerator.TONE_DTMF_4, ToneGenerator.TONE_DTMF_5,
        ToneGenerator.TONE_DTMF_2
    )
    // /Gnutella — the "First Step": dial-up-handshake / beat energy. A punchy low-driving
    //    4-step (the modem reaching out). Re-homes the old COUSINS rising idea.
    private val GNUTELLA_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_1, ToneGenerator.TONE_DTMF_1,
        ToneGenerator.TONE_DTMF_7, ToneGenerator.TONE_DTMF_4
    )

    // ── Spice eggs — each a small DISTINCT cue (2–3 notes), recognizably its own.
    // /truth — the meta-answer: a single resolving "reveal" two-note (low→high open).
    private val TRUTH_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_S, ToneGenerator.TONE_DTMF_9
    )
    // /yeah — the name story: a bright triumphant up-blip (the "Yeah!").
    private val YEAH_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_6, ToneGenerator.TONE_DTMF_C
    )
    // /help — a neutral "menu" double-beep (flat, utilitarian, distinct from the others).
    private val HELP_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_5, ToneGenerator.TONE_DTMF_5
    )
    // /eminem (hidden) — a 3-note staccato beat-nod (original rhythm, no quoted track).
    private val EMINEM_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_1, ToneGenerator.TONE_DTMF_4, ToneGenerator.TONE_DTMF_1
    )
    // /einstein (hidden) — a quirky zig-zag (up-down-up-down) "idea every four minutes".
    private val EINSTEIN_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_2, ToneGenerator.TONE_DTMF_8,
        ToneGenerator.TONE_DTMF_5, ToneGenerator.TONE_DTMF_P
    )

    // ── The reverse-crawl "theme": a NEW original melodic credits-MARCH; the unlock plays this
    //    REVERSED + 5× faster (see [playReverseTheme]). 8 notes so the reversal is audibly a
    //    different, faster phrase than the forward march.
    private val CREDITS_THEME_SEQ = intArrayOf(
        ToneGenerator.TONE_DTMF_1, ToneGenerator.TONE_DTMF_3,
        ToneGenerator.TONE_DTMF_5, ToneGenerator.TONE_DTMF_6,
        ToneGenerator.TONE_DTMF_9, ToneGenerator.TONE_DTMF_6,
        ToneGenerator.TONE_DTMF_5, ToneGenerator.TONE_DTMF_3
    )

    /**
     * The slash-command → [Egg] map: the single source of truth for the AUDIO LAW binding.
     * Keys are lowercase, leading-slash stripped — match with `cmd.trimStart('/').lowercase()`,
     * so `/Satoshi` and `/satoshi` both resolve. [EggConsoleSheet] resolves a typed/tapped
     * command to its egg via [eggForSlash]. [Egg.CREDITS_THEME] is intentionally absent (it is
     * the reverse-crawl theme, not a /slash egg).
     */
    private val SLASH_EGG: Map<String, Egg> = mapOf(
        "satoshi" to Egg.SATOSHI,
        "conrad" to Egg.CONRAD,
        "joe" to Egg.JOE,
        "gnutella" to Egg.GNUTELLA,
        "truth" to Egg.TRUTH,
        "yeah" to Egg.YEAH,
        "help" to Egg.HELP,
        "eminem" to Egg.EMINEM,     // hidden
        "einstein" to Egg.EINSTEIN  // hidden
    )

    /**
     * Resolve a typed or tapped slash command (e.g. "/Satoshi", "satoshi") to its [Egg],
     * or null if unrecognized. Lowercase + leading-slash-tolerant. Never throws.
     */
    @JvmStatic
    fun eggForSlash(command: String?): Egg? {
        if (command.isNullOrBlank()) return null
        return SLASH_EGG[command.trim().trimStart('/').lowercase()]
    }

    /**
     * Fire-and-forget: play this egg's OWN distinct short chiptune motif (the AUDIO LAW).
     * NEVER crashes; respects system mute/volume; retains nothing. The no-arg-default overload
     * keeps every existing caller (and any test) source-compatible.
     */
    @JvmOverloads
    fun playCue(egg: Egg, noteMs: Int = NOTE_MS, gapMs: Long = GAP_MS) {
        val seq = when (egg) {
            Egg.SATOSHI -> SATOSHI_SEQ
            Egg.CONRAD -> CONRAD_SEQ
            Egg.JOE -> JOE_SEQ
            Egg.GNUTELLA -> GNUTELLA_SEQ
            Egg.TRUTH -> TRUTH_SEQ
            Egg.YEAH -> YEAH_SEQ
            Egg.HELP -> HELP_SEQ
            Egg.EMINEM -> EMINEM_SEQ
            Egg.EINSTEIN -> EINSTEIN_SEQ
            Egg.CREDITS_THEME -> CREDITS_THEME_SEQ
        }
        playSequence(seq, noteMs, gapMs)
    }

    /**
     * The credits-march chiptune played REVERSED + 5× faster — the audio twin of the reverse-5×
     * crawl fired on the 3rd clean read (AboutActivity wires this at the reverse-crawl start).
     * Original motif only (homage, no real track). Floors note/gap to 1 so the 5× speed-up never
     * produces a 0ms (silent/throwing) tone.
     */
    fun playReverseTheme() {
        val reversed = CREDITS_THEME_SEQ.reversedArray()
        val fastNote = (NOTE_MS / 5).coerceAtLeast(1)   // 140/5 = 28ms
        val fastGap = (GAP_MS / 5).coerceAtLeast(1L)    // 60/5 = 12ms
        playSequence(reversed, fastNote, fastGap)
    }

    @Volatile
    private var themeLoopActive = false

    /**
     * The FORWARD credits-march theme, LOOPING at normal speed — the bound music that plays DURING the
     * forward crawl (the reverse twin is [playReverseTheme]). Idempotent start; ONE leak-safe worker loops
     * [CREDITS_THEME_SEQ] with a short rest between marches while [themeLoopActive], releasing the
     * ToneGenerator on exit. Call [stopCreditsTheme] when the reverse phase begins / the screen leaves.
     */
    fun startCreditsThemeLoop() {
        if (themeLoopActive) return
        themeLoopActive = true
        Thread {
            var tg: ToneGenerator? = null
            try {
                tg = ToneGenerator(AudioManager.STREAM_MUSIC, VOLUME)
                while (themeLoopActive) {
                    for (tone in CREDITS_THEME_SEQ) {
                        if (!themeLoopActive) break
                        try {
                            tg.startTone(tone, NOTE_MS)
                            Thread.sleep((NOTE_MS + GAP_MS))
                        } catch (e: Exception) {
                            loge("EggAudio.creditsTheme note", e)
                        }
                    }
                    try {
                        if (themeLoopActive) Thread.sleep(THEME_LOOP_GAP_MS)
                    } catch (e: Exception) {
                        loge("EggAudio.creditsTheme rest", e)
                    }
                }
            } catch (e: Exception) {
                loge("EggAudio.startCreditsThemeLoop", e)
            } finally {
                try {
                    tg?.release()
                } catch (e: Exception) {
                    loge("EggAudio.creditsTheme.release", e)
                }
            }
        }.start()
    }

    /** Stop the looping forward theme — the worker exits after its current note. Idempotent. */
    fun stopCreditsTheme() {
        themeLoopActive = false
    }

    /**
     * The single play seam — same leak-safe one-shot-thread discipline as the original #96b body.
     * Sequencing + sleeps run off the main thread (avoids UI block/ANR). The ToneGenerator is
     * created, used, and released entirely within this one-shot thread — NO retained object,
     * NO Handler, NO leak. The thread dies when the loop ends.
     */
    private fun playSequence(seq: IntArray, noteMs: Int, gapMs: Long) {
        Thread {
            var tg: ToneGenerator? = null
            try {
                tg = ToneGenerator(AudioManager.STREAM_MUSIC, VOLUME)
                for (tone in seq) {
                    try {
                        tg.startTone(tone, noteMs)        // non-blocking: returns immediately, auto-stops at noteMs
                        Thread.sleep(noteMs + gapMs)      // let it finish + a small gap before the next note
                    } catch (e: Exception) {
                        loge("EggAudio.playSequence note", e)
                    }
                }
            } catch (e: Exception) {
                // ToneGenerator constructor can throw RuntimeException if the audio resource
                // cannot be allocated — swallow it, fail-open (no audio is acceptable).
                loge("EggAudio.playSequence", e)
            } finally {
                try {
                    tg?.release()
                } catch (e: Exception) {
                    loge("EggAudio.release", e)
                }
            }
        }.start()
    }
}
