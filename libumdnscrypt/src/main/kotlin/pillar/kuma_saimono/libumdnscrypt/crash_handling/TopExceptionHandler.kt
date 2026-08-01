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

package pillar.kuma_saimono.libumdnscrypt.crash_handling

import android.content.SharedPreferences
import android.util.Log
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.CRASH_REPORT
import kotlin.system.exitProcess

private const val LOG_TAG = "TPDCLogs"

class TopExceptionHandler(
    private val sharedPreferences: SharedPreferences,
    private val defaultExceptionHandler: Thread.UncaughtExceptionHandler?
) : Thread.UncaughtExceptionHandler {

    override fun uncaughtException(t: Thread, e: Throwable) {

        var arr = e.stackTrace
        var report = e.toString() + "\n\n"
        report += "--------- Stack trace ---------\n\n"
        for (i in arr.indices) {
            report += "    " + arr[i].toString() + "\n"
        }
        report += "-------------------------------\n\n"

        // If the exception was thrown in a background thread inside
        // AsyncTask, then the actual exception can be found with getCause
        val cause = e.cause
        if (cause != null) {
            report += "--------- Cause ---------\n\n"
            report += cause.toString() + "\n\n"
            arr = cause.stackTrace
            for (i in arr.indices) {
                report += "    " + arr[i].toString() + "\n"
            }
            report += "-------------------------------\n\n"
        }

        Log.e(LOG_TAG, report)

        saveReport(report)

        defaultExceptionHandler?.uncaughtException(t, e) ?: exitProcess(2)
    }

    private fun saveReport(report: String) {
        sharedPreferences.edit().putString(CRASH_REPORT, report).commit()
    }
}
