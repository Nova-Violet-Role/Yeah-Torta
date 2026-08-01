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

package pillar.kuma_saimono.libumdnscrypt.patches

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import java.io.File

class ConfigUtil(private val context: Context) {
    private val pathVars = App.instance.daggerComponent.getPathVars().get()

    fun patchDNSCryptConfig(dnsCryptConfigPatches: List<AlterConfig>) {
        readFromFile(pathVars.dnscryptConfPath).run {
            addLinesToFile(dnsCryptConfigPatches.filterIsInstance<AlterConfig.AddLine>())
                .replaceLinesInFile(dnsCryptConfigPatches.filterIsInstance<AlterConfig.ReplaceLine>())
                .addOdohDNSCryptSection(getOdohSection())
                .takeIf { it.size != this.size || !it.containsAll(this) }
                ?.writeToFile(pathVars.dnscryptConfPath)
        }
    }

    private fun readFromFile(filePath: String): List<String> {
        val file = File(filePath)

        return if (file.isFile && (file.canRead() || file.setReadable(true))) {
            file.readLines()
        } else {
            loge("Patches ConfigUtil cannot read from file $filePath")
            emptyList()
        }
    }

    private fun List<String>.writeToFile(filePath: String) {

        if (this.isEmpty()) {
            return
        }

        val file = File(filePath)
        val text = StringBuilder()

        this.forEach { line ->
            if (line.isNotEmpty()) {
                text.append(line).append("\n")
            }
        }

        if (file.isFile && (file.canWrite() || file.setWritable(true))) {
            file.writeText(text.toString())
        } else {
            loge("Patches ConfigUtil cannot write to file $filePath")
        }
    }

    private fun List<String>.addLinesToFile(addLines: List<AlterConfig.AddLine>): List<String> {
        val newLines = mutableListOf<String>()
        val keyRegex = Regex("[ =]")

        this.forEach { line -> newLines.add(line.trim()) }

        var currentHeader = ""
        for (index: Int in newLines.indices) {

            val line = newLines[index]

            if (line.matches(Regex("\\[.+]"))) {
                currentHeader = line
            }

            for (addLine: AlterConfig.AddLine in addLines) {

                val keyToAdd = addLine.lineToAdd.split(keyRegex).firstOrNull() ?: ""
                val existingKey = newLines.find {
                    it.split(keyRegex).firstOrNull()?.trim() == keyToAdd
                }
                if (existingKey != null) {
                    continue
                }

                if ((addLine.header.isEmpty() || addLine.header == currentHeader)
                    && line.matches(addLine.lineToFind)
                ) {
                    newLines.add(index + 1, addLine.lineToAdd)
                }
            }
        }

        return newLines
    }

    private fun List<String>.replaceLinesInFile(replacementLines: List<AlterConfig.ReplaceLine>): List<String> {
        val newLines = mutableListOf<String>()

        this.forEach { line -> newLines.add(line.trim()) }

        var currentHeader = ""
        for (index: Int in newLines.indices) {

            val line = newLines[index]

            if (line.matches(Regex("\\[.+]"))) {
                currentHeader = line
            }

            for (replacementLine: AlterConfig.ReplaceLine in replacementLines) {
                if ((replacementLine.header.isEmpty() || replacementLine.header == currentHeader)
                    && line.matches(replacementLine.lineToFind)
                ) {
                    newLines[index] = replacementLine.lineToReplace
                }
            }
        }

        return newLines
    }

    private fun List<String>.addOdohDNSCryptSection(lines: List<String>): List<String> {

        if (this.contains(lines.first())) {
            return this
        }

        val newLines = mutableListOf<String>()

        this.forEach { line -> newLines.add(line.trim()) }

        var currentHeader = ""
        for (index: Int in newLines.indices) {

            val line = newLines[index]

            if (line.matches(Regex("\\[.+]"))) {
                currentHeader = line
            }

            if (currentHeader == "[sources.'relays']" && line == "prefix = ''") {
                newLines.addAll(index + 1, lines)
                break
            }
        }

        return newLines
    }

    private fun getOdohSection() =
        """
            [sources.'odoh-servers']
            urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md', 'https://ipv6.download.dnscrypt.info/resolvers-list/v3/odoh-servers.md']
            cache_file = 'odoh-servers.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''
            [sources.'odoh-relays']
            urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md', 'https://ipv6.download.dnscrypt.info/resolvers-list/v3/odoh-relays.md']
            cache_file = 'odoh-relays.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''
        """.trimIndent().split("\n")

}
