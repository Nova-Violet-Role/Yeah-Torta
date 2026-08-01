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

package pillar.kuma_saimono.libumdnscrypt.data.dns_rules

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.dns_engine.RuntimeTierManager
import pillar.kuma_saimono.libumdnscrypt.rust.TortaCore
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import java.io.File
import java.io.InputStreamReader
import javax.inject.Inject

class DnsRulesDataSourceImpl @Inject constructor(
    private val context: Context,
    private val pathVars: PathVars
) : DnsRulesDataSource {

    // W5 #12 slice 2 — the app-private DurableTier root the config authority + rotation already use. Each
    // user single-rule list gets a RAM⊗NAND durable mirror under here (a framed per-list record), so a
    // wipe of the loose *-single.txt (the ONLY rule files not re-derivable from a signed remote source) is
    // recoverable. Persist on save; re-materialize lazily on a read that finds the loose file gone.
    private val durableDir: String =
        pathVars.appDataDir + RuntimeTierManager.RUNTIME_TIER_RELATIVE_DIR

    /**
     * Open a user single-rule list for reading, with W5 durable recovery. If the loose file at [path] is
     * present it is read as-is (the loose file stays the authority for a live edit). If it is ABSENT — a
     * wipe/corruption, never an intentional empty (an emptied list is written as a present zero-byte file) —
     * try to re-materialize it from its [record] DurableTier mirror; on success read it back through the
     * unchanged `File(path).reader()` contract, else concede null (a true cold start). Off the resolve path.
     */
    private fun singleRulesStream(path: String, record: String): InputStreamReader? {
        val file = File(path)
        if (file.isFile) {
            return file.reader()
        }
        if (TortaCore.materializeDnsRuleList(durableDir, record, path) && file.isFile) {
            return file.reader()
        }
        return null
    }

    override fun getBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptBlackListPath)
    }

    override fun getSingleBlacklistRulesStream(): InputStreamReader? {
        return singleRulesStream(pathVars.dnsCryptSingleBlackListPath, DnsSingleRuleRecords.BLACKLIST)
    }

    override fun saveSingleBlacklistRules(rules: List<String>) {
        FileManager.writeTextFileSynchronous(context, pathVars.dnsCryptSingleBlackListPath, rules)
        TortaCore.persistDnsRuleList(durableDir, DnsSingleRuleRecords.BLACKLIST, rules)
    }

    override fun getRemoteBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptRemoteBlackListPath)
    }

    override fun getRemoteBlacklistRulesFileSize(): Long {
        return File(pathVars.dnsCryptRemoteBlackListPath).length()
    }

    override fun getRemoteBlacklistRulesFileDate(): Long {
        return File(pathVars.dnsCryptRemoteBlackListPath).lastModified()
    }

    override fun clearRemoteBlacklistRules() {
        File(pathVars.dnsCryptRemoteBlackListPath).printWriter().use {
            println()
        }
    }

    override fun getLocalBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptLocalBlackListPath)
    }

    override fun clearLocalBlacklistRules() {
        File(pathVars.dnsCryptLocalBlackListPath).printWriter().use {
            println()
        }
    }

    override fun getLocalBlacklistRulesFileSize(): Long {
        return File(pathVars.dnsCryptLocalBlackListPath).length()
    }

    override fun getLocalBlacklistRulesFileDate(): Long {
        return File(pathVars.dnsCryptLocalBlackListPath).lastModified()
    }

    override fun getWhitelistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptWhiteListPath)
    }

    override fun getSingleWhitelistRulesStream(): InputStreamReader? {
        return singleRulesStream(pathVars.dnsCryptSingleWhiteListPath, DnsSingleRuleRecords.WHITELIST)
    }

    override fun saveSingleWhitelistRules(rules: List<String>) {
        FileManager.writeTextFileSynchronous(context, pathVars.dnsCryptSingleWhiteListPath, rules)
        TortaCore.persistDnsRuleList(durableDir, DnsSingleRuleRecords.WHITELIST, rules)
    }

    override fun getRemoteWhitelistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptRemoteWhiteListPath)
    }

    override fun getRemoteWhitelistRulesFileSize(): Long {
        return File(pathVars.dnsCryptRemoteWhiteListPath).length()
    }

    override fun getRemoteWhitelistRulesFileDate(): Long {
        return File(pathVars.dnsCryptRemoteWhiteListPath).lastModified()
    }

    override fun clearRemoteWhitelistRules() {
        File(pathVars.dnsCryptRemoteWhiteListPath).printWriter().use {
            println()
        }
    }

    override fun getLocalWhitelistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptLocalWhiteListPath)
    }

    override fun getLocaleWhitelistRulesFileSize(): Long {
        return File(pathVars.dnsCryptLocalWhiteListPath).length()
    }

    override fun getLocalWhitelistRulesFileDate(): Long {
        return File(pathVars.dnsCryptLocalWhiteListPath).lastModified()
    }

    override fun clearLocalWhitelistRules() {
        File(pathVars.dnsCryptLocalWhiteListPath).printWriter().use {
            println()
        }
    }

    override fun getIpBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptIPBlackListPath)
    }

    override fun getSingleIpBlacklistRulesStream(): InputStreamReader? {
        return singleRulesStream(pathVars.dnsCryptSingleIPBlackListPath, DnsSingleRuleRecords.IP_BLACKLIST)
    }

    override fun saveSingleIpBlacklistRules(rules: List<String>) {
        FileManager.writeTextFileSynchronous(context, pathVars.dnsCryptSingleIPBlackListPath, rules)
        TortaCore.persistDnsRuleList(durableDir, DnsSingleRuleRecords.IP_BLACKLIST, rules)
    }

    override fun getRemoteIpBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptRemoteIPBlackListPath)
    }

    override fun getRemoteIpBlacklistRulesFileSize(): Long {
        return File(pathVars.dnsCryptRemoteIPBlackListPath).length()
    }

    override fun getRemoteIpBlacklistRulesFileDate(): Long {
        return File(pathVars.dnsCryptRemoteIPBlackListPath).lastModified()
    }

    override fun clearRemoteIpBlacklistRules() {
        File(pathVars.dnsCryptRemoteIPBlackListPath).printWriter().use {
            println()
        }
    }

    override fun getLocalIpBlacklistRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptLocalIPBlackListPath)
    }

    override fun getLocalIpBlacklistRulesFileSize(): Long {
        return File(pathVars.dnsCryptLocalIPBlackListPath).length()
    }

    override fun getLocalIpBlacklistRulesFileDate(): Long {
        return File(pathVars.dnsCryptLocalIPBlackListPath).lastModified()
    }

    override fun clearLocalIpBlacklistRules() {
        File(pathVars.dnsCryptLocalIPBlackListPath).printWriter().use {
            println()
        }
    }

    override fun getForwardingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptForwardingRulesPath)
    }

    override fun getSingleForwardingRulesStream(): InputStreamReader? {
        return singleRulesStream(pathVars.dnsCryptSingleForwardingRulesPath, DnsSingleRuleRecords.FORWARDING)
    }

    override fun saveSingleForwardingRules(rules: List<String>) {
        FileManager.writeTextFileSynchronous(
            context,
            pathVars.dnsCryptSingleForwardingRulesPath,
            rules
        )
        TortaCore.persistDnsRuleList(durableDir, DnsSingleRuleRecords.FORWARDING, rules)
    }

    override fun getRemoteForwardingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptRemoteForwardingRulesPath)
    }

    override fun getRemoteForwardingRulesFileSize(): Long {
        return File(pathVars.dnsCryptRemoteForwardingRulesPath).length()
    }

    override fun getRemoteForwardingRulesFileDate(): Long {
        return File(pathVars.dnsCryptRemoteForwardingRulesPath).lastModified()
    }

    override fun clearRemoteForwardingRules() {
        File(pathVars.dnsCryptRemoteForwardingRulesPath).printWriter().use {
            println()
        }
    }

    override fun getLocalForwardingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptLocalForwardingRulesPath)
    }

    override fun getLocalForwardingRulesFileSize(): Long {
        return File(pathVars.dnsCryptLocalForwardingRulesPath).length()
    }

    override fun getLocalForwardingRulesFileDate(): Long {
        return File(pathVars.dnsCryptLocalForwardingRulesPath).lastModified()
    }

    override fun clearLocalForwardingRules() {
        File(pathVars.dnsCryptLocalForwardingRulesPath).printWriter().use {
            println()
        }
    }

    override fun getCloakingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptCloakingRulesPath)
    }

    override fun getSingleCloakingRulesStream(): InputStreamReader? {
        return singleRulesStream(pathVars.dnsCryptSingleCloakingRulesPath, DnsSingleRuleRecords.CLOAKING)
    }

    override fun saveSingleCloakingRules(rules: List<String>) {
        FileManager.writeTextFileSynchronous(
            context,
            pathVars.dnsCryptSingleCloakingRulesPath,
            rules
        )
        TortaCore.persistDnsRuleList(durableDir, DnsSingleRuleRecords.CLOAKING, rules)
    }

    override fun getRemoteCloakingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptRemoteCloakingRulesPath)
    }

    override fun getRemoteCloakingRulesFileSize(): Long {
        return File(pathVars.dnsCryptRemoteCloakingRulesPath).length()
    }

    override fun getRemoteCloakingRulesFileDate(): Long {
        return File(pathVars.dnsCryptRemoteCloakingRulesPath).lastModified()
    }

    override fun clearRemoteCloakingRules() {
        File(pathVars.dnsCryptRemoteCloakingRulesPath).printWriter().use {
            println()
        }
    }

    override fun getLocalCloakingRulesStream(): InputStreamReader {
        return getInputStreamFromFile(pathVars.dnsCryptLocalCloakingRulesPath)
    }

    override fun getLocalCloakingRulesFileSize(): Long {
        return File(pathVars.dnsCryptLocalCloakingRulesPath).length()
    }

    override fun getLocalCloakingRulesFileDate(): Long {
        return File(pathVars.dnsCryptLocalCloakingRulesPath).lastModified()
    }

    override fun clearLocalCloakingRules() {
        File(pathVars.dnsCryptLocalCloakingRulesPath).printWriter().use {
            println()
        }
    }

    private fun getInputStreamFromFile(path: String): InputStreamReader {
        val file = File(path)
        if (!file.isFile) {
            file.createNewFile()
        }
        return file.reader()
    }
}
