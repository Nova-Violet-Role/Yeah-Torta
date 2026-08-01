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

package pillar.kuma_saimono.libumdnscrypt.data.log_reader

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.domain.log_reader.ModulesLogRepository
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.connectionchecker.NetworkChecker
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import javax.inject.Inject
import kotlin.text.endsWith

private val asciiVisibleSymbols = 32..126

// #120 — the DnsCrypt.log tail window served by the Rust RAM⊗NAND fast-tier (matches OwnFileReader's
// MAX_LINES_QUANTITY so the parser sees the identical recent-line window it always has).
private const val DNSCRYPT_TAIL_LINES = 80

class ModulesLogRepositoryImpl @Inject constructor(
    val applicationContext: Context,
    pathVars: PathVars
) : ModulesLogRepository {

    private val appDataDir = pathVars.appDataDir
    private var dnsCryptLogFileReader: OwnFileReader? = null
    private var torLogFileReader: OwnFileReader? = null
    private var itpdLogFileReader: OwnFileReader? = null
    private var itpdHtmlFileReader: HtmlReader? = null

    private val dnsCryptLog: MutableList<String> = arrayListOf()
    private val torLog: MutableList<String> = arrayListOf()
    private val itpdLog: MutableList<String> = arrayListOf()

    @Volatile
    private var dnsCryptLogLength = 0L

    @Volatile
    private var torLogLength = 0L

    @Volatile
    private var itpdLogLength = 0L

    override fun getDNSCryptLog(): List<String> {
        val path = "$appDataDir/logs/DnsCrypt.log"
        dnsCryptLogFileReader = dnsCryptLogFileReader ?: OwnFileReader(
            applicationContext,
            path
        )

        return dnsCryptLogFileReader?.let { reader ->
            val length = reader.fileLength
            if (length < 0 || length > 0 && length != dnsCryptLogLength) {
                dnsCryptLogLength = length
                dnsCryptLog.clear()
                // #120 RAM⊗NAND fast-tier: tail the new bytes in Rust (incremental, one ring read) instead
                // of OwnFileReader's full re-read + FileShortener rewrite every grow-tick — the IO spike.
                // dnscrypt bounds the file itself (log_files_max_size=1MB), so the Kotlin shortener is moot.
                // Null ⇒ a stale/base .so without the export ⇒ fall back to the original full-reader (no regression).
                val rust = TortaCore.logTailRecent(path, DNSCRYPT_TAIL_LINES)
                val lines = when {
                    rust == null -> reader.readLastLines()
                    rust.isEmpty() -> emptyList()
                    else -> rust.split("\n")
                }
                dnsCryptLog.addAll(lines.map { it.removeNonVisibleSymbols() })
            }
            dnsCryptLog
        } ?: emptyList()
    }

    override fun getTorLog(): List<String> {
        torLogFileReader = torLogFileReader ?: OwnFileReader(
            applicationContext,
            "$appDataDir/logs/Tor.log"
        )

        return torLogFileReader?.let { reader ->
            val length = reader.fileLength
            if (length < 0 || length > 0 && length != torLogLength) {
                torLogLength = length
                torLog.clear()
                torLog.addAll(reader.readLastLines())
            }
            val filtered = if (NetworkChecker.isNetworkAvailable(applicationContext)) {
                torLog
            } else {
                filterBridgesWarning(torLog)
            }
            if (filtered.isNotEmpty() && filtered.size != torLog.size) {
                reader.updateLines(filtered)
            }
            if (filtered.isNotEmpty()) {
                filtered
            } else {
                torLog
            }
        } ?: emptyList()
    }

    private fun filterBridgesWarning(lines: List<String>): List<String> {
        return lines.filter { !it.endsWith("(\"general SOCKS server failure\")") }
    }

    override fun getITPDLog(): List<String> {
        itpdLogFileReader = itpdLogFileReader ?: OwnFileReader(
            applicationContext,
            "$appDataDir/logs/i2pd.log"
        )

        return itpdLogFileReader?.let { reader ->
            val length = reader.fileLength
            if (length < 0 || length > 0 && length != itpdLogLength) {
                itpdLogLength = length
                itpdLog.clear()
                itpdLog.addAll(reader.readLastLines())
            }
            itpdLog
        } ?: emptyList()
    }

    override fun getITPDHtmlData(): List<String> {
        itpdHtmlFileReader = itpdHtmlFileReader ?: HtmlReader(7070)
        return itpdHtmlFileReader?.readLines() ?: emptyList()
    }

    private fun String.removeNonVisibleSymbols(): String {
        var result: StringBuilder? = null
        for (ch in toCharArray()) {
            if (ch.code !in asciiVisibleSymbols) {
                result = StringBuilder()
                loge("DNSCrypt log contains non-visible symbols: ${ch.code} Line: $this")
                break
            }
        }
        if (result != null) {
            for (ch in toCharArray()) {
                if (ch.code in asciiVisibleSymbols) {
                    result.append(ch)
                }
            }
        }
        return result?.let {
            result.toString()
        } ?: this
    }
}
