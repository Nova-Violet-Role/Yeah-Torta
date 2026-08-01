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

package pillar.kuma_saimono.libumdnscrypt.utils.filemanager

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import dagger.Lazy
import pillar.kuma_saimono.libumdnscrypt.App
import pillar.kuma_saimono.libumdnscrypt.domain.preferences.PreferenceRepository
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.enums.FileOperationsVariants
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import pillar.kuma_saimono.libumdnscrypt.utils.preferences.TortaeKeys.ROOT_IS_AVAILABLE
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommands
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootCommandsMark
import pillar.kuma_saimono.libumdnscrypt.utils.root.RootExecService
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.io.PrintWriter
import java.util.Objects
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.inject.Inject

class FileManager {

    @Inject
    lateinit var preferenceRepository: Lazy<PreferenceRepository>

    private var latch: CountDownLatch? = null

    init {
        App.instance.daggerComponent.inject(this)
    }

    private var br: BroadcastReceiver? = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            if (intent != null) {
                val action = intent.action
                if (action == null
                    || action == ""
                    || (intent.getIntExtra("Mark", 0) != RootCommandsMark.FILE_OPERATIONS_MARK)
                ) return

                logi("FileOperations onReceive")

                if (action == RootExecService.COMMAND_RESULT) {
                    continueFileOperations()
                    if (br != null)
                        LocalBroadcastManager.getInstance(context).unregisterReceiver(br!!)
                    br = null
                }
            }

        }
    }

    fun restoreAccess(context: Context?, filePath: String) {
        if (context != null) {
            val rootIsAvailable = preferenceRepository.get().getBoolPreference(ROOT_IS_AVAILABLE)

            if (!rootIsAvailable) {
                return
            }

            val intentFilterBckgIntSer = IntentFilter(RootExecService.COMMAND_RESULT)
            LocalBroadcastManager.getInstance(context).registerReceiver(br!!, intentFilterBckgIntSer)

            val pathVars = App.instance.daggerComponent.getPathVars().get()
            val appUID = pathVars.appUidStr
            val commands: List<String> = arrayListOf(
                pathVars.busyboxPath + "chown -R " + appUID + "." + appUID + " " + filePath + " 2> /dev/null",
                "restorecon " + filePath + " 2> /dev/null",
                pathVars.busyboxPath + "sleep 1 2> /dev/null"
            )

            RootCommands.execute(context, commands, RootCommandsMark.FILE_OPERATIONS_MARK)

            waitRestoreAccessWithRoot()
        }
    }

    private fun waitRestoreAccessWithRoot() {
        latch = CountDownLatch(1)
        try {
            latch!!.await(3, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            logw("FileOperations latch interrupted", e)
        }
    }

    private fun continueFileOperations() {
        latch!!.countDown()
    }

    companion object {

        private val reentrantLock = ReentrantLock()
        private var callback: OnFileOperationsCompleteListener? = null
        private var stackCallbacks: CopyOnWriteArrayList<OnFileOperationsCompleteListener>? = null
        private var executorService: ExecutorService = Executors.newSingleThreadExecutor()

        @SuppressLint("SetWorldReadable")
        fun moveBinaryFile(context: Context?, inputPath: String, inputFile: String, outputPath: String, tag: String) {

            val runnable = Runnable {

                reentrantLock.lock()

                try {
                    val dir = File(outputPath)
                    if (!dir.isDirectory) {
                        if (!dir.mkdirs()) {
                            throw IllegalStateException("Unable to create dir " + dir)
                        }

                        if (!dir.canRead() || !dir.canWrite()) {
                            if (!dir.setReadable(true) || !dir.setWritable(true)) {
                                logw("Unable to chmod dir " + dir)
                            }
                        }
                    }

                    val oldFile = File(outputPath + "/" + inputFile)
                    if (oldFile.exists()) {
                        if (deleteFileSynchronous(context, outputPath, inputFile)) {
                            throw IllegalStateException("Unable to delete file " + oldFile)
                        }
                    }

                    var inFile: File? = null

                    try {
                        inFile = File(inputPath + "/" + inputFile)
                    } catch (e: Exception) {
                        logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                    }

                    if (inFile == null) {
                        throw IllegalStateException("File is no accessible " + inputPath + "/" + inputFile)
                    }

                    if (!inFile.canRead()) {
                        if (!inFile.setReadable(true)) {
                            logw("Unable to chmod file " + inFile)
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, inFile.path)
                        } else if (!inFile.canRead()) {
                            throw IllegalStateException("Unable to chmod file " + inFile)
                        }
                    }

                    val buffer = ByteArray(1024)
                    var read = 0

                    FileInputStream(inputPath + "/" + inputFile).use { inStream ->
                        FileOutputStream(outputPath + "/" + inputFile).use { outStream ->
                            while (inStream.read(buffer).also { read = it } != -1) {
                                outStream.write(buffer, 0, read)
                            }
                        }
                    }

                    val newFile = File(outputPath + "/" + inputFile)
                    if (!newFile.exists()) {
                        throw IllegalStateException("New file not exist " + oldFile)
                    }

                    if (tag.contains("executable")) {
                        if (!newFile.setReadable(true, false) || !newFile.setWritable(true) || !newFile.setExecutable(true, false)) {
                            throw IllegalStateException("Chmod exec file fault " + outputPath + "/" + inputFile)
                        }
                    }

                    // delete the unwanted file
                    if (deleteFileSynchronous(context, inputPath, inputFile)) {
                        throw IllegalStateException("Unable to delete file " + inputFile)
                    }

                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.moveBinaryFile, true, outputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }
                    }

                } catch (e: Exception) {
                    loge("moveBinaryFile function fault", e)
                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.moveBinaryFile, false, outputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }
                    }
                } finally {
                    reentrantLock.unlock()
                }
            }

            if (executorService.isShutdown) {
                executorService = Executors.newSingleThreadExecutor()
            }
            executorService.execute(runnable)
        }

        fun copyBinaryFile(context: Context?, inputPath: String, inputFile: String, outputPath: String, tag: String) {

            val runnable = Runnable {

                reentrantLock.lock()

                try {
                    val dir = File(outputPath)
                    if (!dir.isDirectory) {
                        if (!dir.mkdirs()) {
                            throw IllegalStateException("Unable to create dir " + dir)
                        }

                        if (!dir.canRead() || !dir.canWrite()) {
                            if (!dir.setReadable(true) || !dir.setWritable(true)) {
                                logw("Unable to chmod dir " + dir)
                            }
                        }
                    }

                    val oldFile = File(outputPath + "/" + inputFile)
                    if (oldFile.exists()) {
                        if (deleteFileSynchronous(context, outputPath, inputFile)) {
                            throw IllegalStateException("Unable to delete file " + oldFile)
                        }
                    }

                    var inFile: File? = null

                    try {
                        inFile = File(inputPath + "/" + inputFile)
                    } catch (e: Exception) {
                        logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                    }

                    if (inFile == null) {
                        throw IllegalStateException("File is no accessible " + inputPath + "/" + inputFile)
                    }

                    if (!inFile.canRead()) {
                        if (!inFile.setReadable(true)) {
                            logw("Unable to chmod file " + inFile)
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, inFile.path)
                        } else if (!inFile.canRead()) {
                            throw IllegalStateException("Unable to chmod file " + inFile)
                        }
                    }

                    val buffer = ByteArray(1024)
                    var read = 0

                    FileInputStream(inputPath + "/" + inputFile).use { inStream ->
                        FileOutputStream(outputPath + "/" + inputFile).use { outStream ->
                            while (inStream.read(buffer).also { read = it } != -1) {
                                outStream.write(buffer, 0, read)
                            }
                        }
                    }

                    val newFile = File(outputPath + "/" + inputFile)
                    if (!newFile.exists()) {
                        throw IllegalStateException("New file not exist " + oldFile)
                    }

                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.copyBinaryFile, true, outputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }

                    }


                } catch (e: Exception) {
                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.copyBinaryFile, false, outputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }
                    }
                    loge("copyBinaryFile function fault", e)
                } finally {
                    reentrantLock.unlock()
                }

            }

            if (executorService.isShutdown) {
                executorService = Executors.newSingleThreadExecutor()
            }
            executorService.execute(runnable)
        }

        private fun copyBinaryFileSynchronous(context: Context?, inputPath: String,
                                              inputFile: String, outputPath: String) {

            reentrantLock.lock()

            try {
                val dir = File(outputPath)
                if (!dir.isDirectory) {
                    if (!dir.mkdirs()) {
                        throw IllegalStateException("Unable to create dir " + dir)
                    }

                    if (!dir.canRead() || !dir.canWrite()) {
                        if (!dir.setReadable(true) || !dir.setWritable(true)) {
                            logw("Unable to chmod dir " + dir)
                        }
                    }
                }

                val oldFile = File(outputPath + "/" + inputFile)
                if (oldFile.exists()) {
                    if (deleteFileSynchronous(context, outputPath, inputFile)) {
                        throw IllegalStateException("Unable to delete file " + oldFile)
                    }
                }

                var inFile: File? = null

                try {
                    inFile = File(inputPath + "/" + inputFile)
                } catch (e: Exception) {
                    logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                }

                if (inFile == null) {
                    throw IllegalStateException("File is no accessible " + inputPath + "/" + inputFile)
                }

                if (!inFile.canRead()) {
                    if (!inFile.setReadable(true)) {
                        logw("Unable to chmod file " + inFile)
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inFile.path)
                    } else if (!inFile.canRead()) {
                        throw IllegalStateException("Unable to chmod file " + inFile)
                    }
                }

                val buffer = ByteArray(1024)
                var read = 0

                FileInputStream(inputPath + "/" + inputFile).use { inStream ->
                    FileOutputStream(outputPath + "/" + inputFile).use { outStream ->
                        while (inStream.read(buffer).also { read = it } != -1) {
                            outStream.write(buffer, 0, read)
                        }
                    }
                }

                val newFile = File(outputPath + "/" + inputFile)
                if (!newFile.exists()) {
                    throw IllegalStateException("New file not exist " + oldFile)
                }

            } catch (e: Exception) {
                loge("copyBinaryFileSynchronous function fault", e)
            } finally {
                reentrantLock.unlock()
            }

        }

        fun copyFolderSynchronous(context: Context?, inputPath: String, outputPath: String) {

            reentrantLock.lock()

            try {
                var inDir: File? = null

                try {
                    inDir = File(inputPath)
                } catch (e: Exception) {
                    logw("Dir is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath)
                }

                if (inDir == null) {
                    throw IllegalStateException("File is no accessible " + inputPath)
                }

                if (!inDir.canRead()) {
                    if (!inDir.setReadable(true)) {
                        logw("Unable to chmod dir " + inDir)
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inDir.path)
                    } else if (!inDir.canRead()) {
                        throw IllegalStateException("Unable to chmod dir " + inDir)
                    }
                }

                val outDir = File(outputPath + "/" + inDir.name)
                if (!outDir.isDirectory) {
                    if (!outDir.mkdirs()) {
                        throw IllegalStateException("Unable to create dir " + outDir)
                    }
                }

                if (!outDir.setReadable(true) || !outDir.setWritable(true) || !outDir.setExecutable(true)) {
                    logw("Unable to chmod dir " + outDir)
                }

                for (file in Objects.requireNonNull(inDir.listFiles())) {

                    if (file.isFile) {
                        copyBinaryFileSynchronous(context, inputPath, file.name, outDir.canonicalPath)
                    } else if (file.isDirectory) {
                        copyFolderSynchronous(context, file.canonicalPath, outDir.canonicalPath)
                    } else {
                        throw IllegalStateException("copyFolderSynchronous cannot copy "
                                + inDir + " because this is no file and no dir")
                    }

                }

            } catch (e: Exception) {
                loge("copyFolderSynchronous function fault", e)
            } finally {
                reentrantLock.unlock()
            }
        }

        fun deleteFileSynchronous(context: Context?, inputPath: String?, inputFile: String): Boolean {

            reentrantLock.lock()

            try {
                var usedFile: File? = null

                try {
                    usedFile = File(inputPath + "/" + inputFile)
                } catch (e: Exception) {
                    logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                }

                if (usedFile == null) {
                    throw IllegalStateException("File is no accessible " + inputPath + "/" + inputFile)
                }

                if (usedFile.exists()) {
                    if (!usedFile.canRead() || !usedFile.canWrite()) {
                        if (!usedFile.setReadable(true) || !usedFile.setWritable(true)) {
                            logw("Unable to chmod file " + inputPath + "/" + inputFile)
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                        } else if (!usedFile.setReadable(true) || !usedFile.setWritable(true)) {
                            loge("Unable to chmod file " + inputPath + "/" + inputFile)
                            return true
                        }
                    }
                    if (!usedFile.delete()) {
                        logw("Unable to delete file " + usedFile + " Try restore access!")

                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inputPath + "/" + inputFile)

                        if (!usedFile.delete()) {
                            loge("Unable to delete file " + usedFile)
                        }

                        return true
                    }
                } else {
                    logw("Unable to delete file internal function. No file " + usedFile)
                    return false
                }
            } catch (e: Exception) {
                if (e.message != null && e.message!!.contains("Permission denied")) {
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                }

                loge("deleteFileSynchronous function fault", e)
                return true
            } finally {
                reentrantLock.unlock()
            }

            return false
        }

        fun deleteFile(context: Context?, inputPath: String, inputFile: String, tag: String) {
            val runnable = Runnable {
                reentrantLock.lock()

                try {
                    var usedFile: File? = null

                    try {
                        usedFile = File(inputPath + "/" + inputFile)
                    } catch (e: Exception) {
                        logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                    }

                    if (usedFile == null) {
                        throw IllegalStateException("File is no accessible " + inputPath + "/" + inputFile)
                    }

                    if (usedFile.exists()) {
                        if (!usedFile.canRead() || !usedFile.canWrite()) {
                            if (!usedFile.setReadable(true) || !usedFile.setWritable(true)) {
                                logw("Unable to chmod file " + inputPath + "/" + inputFile)
                                val fileManager = FileManager()
                                fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                            } else if (!usedFile.setReadable(true) || !usedFile.setWritable(true)) {
                                loge("Unable to chmod file " + inputPath + "/" + inputFile)
                            }
                        }
                        if (!usedFile.delete()) {
                            logw("Unable to delete file " + usedFile + " Try restore access!")

                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, inputPath + "/" + inputFile)

                            if (!usedFile.delete()) {
                                throw IllegalStateException("Unable to delete file " + usedFile)
                            }
                        }
                    } else {
                        logw("Unable to delete file. No file " + usedFile)
                    }

                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.deleteFile, true, inputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }
                    }
                } catch (e: Exception) {
                    loge("deleteFile function fault", e)
                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnBinaryFileOperationsCompleteListener) {
                            (callback as OnBinaryFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.deleteFile, false, inputPath + "/" + inputFile, tag)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose binary type.")
                        }
                    }

                    if (e.message != null && e.message!!.contains("Permission denied")) {
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, inputPath + "/" + inputFile)
                    }
                } finally {
                    reentrantLock.unlock()
                }
            }

            if (executorService.isShutdown) {
                executorService = Executors.newSingleThreadExecutor()
            }
            executorService.execute(runnable)
        }

        fun deleteDirSynchronous(context: Context?, inputPath: String): Boolean {
            reentrantLock.lock()

            var result = false
            var usedDir: File? = null

            try {

                try {
                    usedDir = File(inputPath)
                } catch (e: Exception) {
                    logw("Dir is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath)
                }

                if (usedDir == null) {
                    throw IllegalStateException("Dir is no accessible " + inputPath)
                }

                if (usedDir.isDirectory) {
                    if (!usedDir.canRead() || !usedDir.canWrite()) {
                        if (!usedDir.setReadable(true) || !usedDir.setWritable(true)) {
                            logw("Unable to chmod dir " + inputPath)
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, inputPath)
                        } else if (!usedDir.setReadable(true) || !usedDir.setWritable(true)) {
                            loge("Unable to chmod dir " + inputPath)
                        }
                    }
                } else {
                    throw IllegalStateException(inputPath + " is not Dir")
                }

                val files = usedDir.listFiles()

                if (files == null) {
                    throw IllegalStateException("Impossible to delete dir, listFiles is null " + inputPath)
                }

                if (files.size != 0) {
                    for (file in files) {
                        if (file.isFile) {
                            deleteFileSynchronous(context, file.parent, file.name)
                        } else if (file.isDirectory) {
                            deleteDirSynchronous(context, file.absolutePath)
                        }
                    }
                }

                if (!usedDir.delete()) {
                    logw("Unable to delete dir " + inputPath + " Try to restore access!")

                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath)

                    if (!usedDir.delete()) {
                        throw IllegalStateException("Impossible to delete empty dir " + inputPath)
                    }
                }

                result = true
            } catch (e: Exception) {
                loge("delete Dir function fault", e)

                if (e.message != null && e.message!!.contains("Permission denied")) {
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, inputPath)
                }
            } finally {
                reentrantLock.unlock()
            }

            return result
        }

        @SuppressLint("SetWorldReadable")
        fun readTextFile(context: Context?, filePath: String, tag: String) {
            val runnable = Runnable {

                reentrantLock.lock()

                try {

                    var f: File? = null

                    try {
                        f = File(filePath)
                    } catch (e: Exception) {
                        logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                    }

                    if (f == null) {
                        throw IllegalStateException("File is no accessible " + filePath)
                    }

                    if (f.isFile) {
                        if (f.canRead() || f.setReadable(true, false)) {
                            logi("readTextFile take " + filePath + " success")
                        } else {
                            logw("readTextFile take " + filePath + " warning")
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, filePath)
                            if (f.setReadable(true, false)) {
                                logi("readTextFile take " + filePath + " success")
                            } else {
                                throw IllegalStateException("readTextFile take " + filePath + " error")
                            }
                        }
                    } else {
                        throw IllegalStateException("readTextFile no file " + filePath)
                    }

                    val linesList: MutableList<String> = ArrayList()

                    try {
                        FileInputStream(filePath).use { fstream ->
                            BufferedReader(InputStreamReader(fstream)).use { br ->
                                var tmp: String? = null
                                while (br.readLine().also { tmp = it } != null) {
                                    linesList.add(tmp!!.trim())
                                }
                            }
                        }
                    } catch (ex: Exception) {
                        if (ex.message != null && ex.message!!.contains("Permission denied")) {
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, filePath)

                            FileInputStream(filePath).use { fstream ->
                                BufferedReader(InputStreamReader(fstream)).use { br ->
                                    var tmp: String? = null
                                    while (br.readLine().also { tmp = it } != null) {
                                        linesList.add(tmp!!.trim())
                                    }
                                }
                            }

                        } else {
                            throw IllegalStateException("readTextFile input stream exception " + ex.message + " " + ex.cause)
                        }
                    }


                    if (callback != null) {
                        if (callback is OnTextFileOperationsCompleteListener) {
                            (callback as OnTextFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.readTextFile, true, filePath, tag, linesList)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose text type.")
                        }
                    }

                } catch (e: Exception) {
                    loge("readTextFile Exception", e)
                    if (callback != null) {
                        if (callback is OnTextFileOperationsCompleteListener) {
                            (callback as OnTextFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.readTextFile, false, filePath, tag, null)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose text type.")
                        }
                    }

                    if (e.message != null && e.message!!.contains("Permission denied")) {
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                    }
                } finally {
                    reentrantLock.unlock()
                }
            }

            if (executorService.isShutdown) {
                executorService = Executors.newSingleThreadExecutor()
            }
            executorService.execute(runnable)
        }

        @SuppressLint("SetWorldReadable")
        fun writeToTextFile(context: Context?, filePath: String, lines: List<String>, tag: String) {
            val runnable = Runnable {

                reentrantLock.lock()

                try {

                    var f: File? = null

                    try {
                        f = File(filePath)
                    } catch (e: Exception) {
                        logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                    }

                    if (f == null) {
                        throw IllegalStateException("File is no accessible " + filePath)
                    }

                    if (f.isFile) {
                        if (f.canRead() && f.canWrite() || f.setReadable(true, false) && f.setWritable(true)) {
                            logi("writeToTextFile writeTo " + filePath + " success")
                        } else {
                            logw("writeToTextFile writeTo " + filePath + " warning")
                            val fileManager = FileManager()
                            fileManager.restoreAccess(context, filePath)
                            if (f.setReadable(true, false) && f.setWritable(true)) {
                                logi("writeToTextFile writeTo " + filePath + " success")
                            } else {
                                throw IllegalStateException("writeToTextFile writeTo " + filePath + " error")
                            }
                        }
                    }

                    val ok = atomicWriteLines(filePath, lines)

                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnTextFileOperationsCompleteListener) {
                            (callback as OnTextFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.writeToTextFile, ok, filePath, tag, null)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose text type.")
                        }
                    }
                } catch (e: Exception) {
                    loge("writeToTextFile", e)
                    if (callback != null && !tag.contains("ignored")) {
                        if (callback is OnTextFileOperationsCompleteListener) {
                            (callback as OnTextFileOperationsCompleteListener).OnFileOperationComplete(
                                FileOperationsVariants.writeToTextFile, false, filePath, tag, null)
                        } else {
                            throw ClassCastException("Wrong File operations type. Choose text type.")
                        }
                    }

                    if (e.message != null && e.message!!.contains("Permission denied")) {
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                    }
                } finally {
                    reentrantLock.unlock()
                }
            }

            if (executorService.isShutdown) {
                executorService = Executors.newSingleThreadExecutor()
            }
            executorService.execute(runnable)
        }

        @SuppressLint("SetWorldReadable")
        fun readTextFileSynchronous(context: Context?, filePath: String): MutableList<String> {

            reentrantLock.lock()

            val lines: MutableList<String> = ArrayList()

            try {

                var f: File? = null

                try {
                    f = File(filePath)
                } catch (e: Exception) {
                    logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, filePath)
                }

                if (f == null) {
                    throw IllegalStateException("File is no accessible " + filePath)
                }

                if (f.isFile) {
                    if (f.canRead() || f.setReadable(true, false)) {
                        logi("readTextFileSynchronous take " + filePath + " success")
                    } else {
                        logw("readTextFileSynchronous take " + filePath + " warning")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                        if (f.setReadable(true, false)) {
                            logi("readTextFileSynchronous take " + filePath + " success")
                        } else {
                            throw IllegalStateException("readTextFileSynchronous take " + filePath + " error")
                        }
                    }
                } else {
                    throw IllegalStateException("readTextFileSynchronous no file " + filePath)
                }

                try {
                    FileInputStream(filePath).use { fstream ->
                        BufferedReader(InputStreamReader(fstream)).use { br ->
                            var tmp: String? = null
                            while (br.readLine().also { tmp = it } != null && !Thread.currentThread().isInterrupted) {
                                lines.add(tmp!!.trim())
                            }
                        }
                    }
                } catch (ex: Exception) {
                    if (ex.message != null && ex.message!!.contains("Permission denied")) {
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)

                        FileInputStream(filePath).use { fstream ->
                            BufferedReader(InputStreamReader(fstream)).use { br ->
                                var tmp: String? = null
                                while (br.readLine().also { tmp = it } != null && !Thread.currentThread().isInterrupted) {
                                    lines.add(tmp!!.trim())
                                }
                            }
                        }

                    } else {
                        throw IllegalStateException("readTextFile synchronous input stream exception " + ex.message + " " + ex.cause)
                    }
                }

            } catch (e: Exception) {
                loge("readTextFileSynchronous", e)

                if (e.message != null && e.message!!.contains("Permission denied")) {
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, filePath)
                }
            } finally {
                reentrantLock.unlock()
            }

            return lines
        }

        @SuppressLint("SetWorldReadable")
        fun writeTextFileSynchronous(context: Context?, filePath: String, lines: List<String>): Boolean {

            reentrantLock.lock()

            var result = true
            try {

                var f: File? = null

                try {
                    f = File(filePath)
                } catch (e: Exception) {
                    logw("File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, filePath)
                }

                if (f == null) {
                    throw IllegalStateException("File is no accessible " + filePath)
                }

                if (f.isFile) {
                    if (f.canRead() && f.canWrite() || f.setReadable(true, false) && f.setWritable(true)) {
                        logi("writeTextFileSynchronous writeTo " + filePath + " success")
                    } else {
                        logw("writeTextFileSynchronous writeTo " + filePath + " warning")
                        val fileManager = FileManager()
                        fileManager.restoreAccess(context, filePath)
                        if (f.setReadable(true, false) && f.setWritable(true)) {
                            logi("writeTextFileSynchronous writeTo " + filePath + " success")
                        } else {
                            throw IllegalStateException("writeTextFileSynchronous writeTo " + filePath + " error")
                        }
                    }
                }

                if (!atomicWriteLines(filePath, lines)) {
                    result = false
                }
            } catch (e: Exception) {
                loge("writeTextFileSynchronous", e)
                result = false

                if (e.message != null && e.message!!.contains("Permission denied")) {
                    val fileManager = FileManager()
                    fileManager.restoreAccess(context, filePath)
                }
            } finally {
                reentrantLock.unlock()
            }

            return result
        }

        // RAM(x)NAND Opt-1 (#11): crash-safe, wear-frugal line write.
        //
        // Two guarantees the raw PrintWriter(filePath) it replaces did not give:
        //   (a) ATOMIC  - the bytes land in <target>.tmp and are fsync'd, then a
        //                 single rename swaps them over the target. A crash mid-
        //                 write can only leave the OLD complete file or the NEW
        //                 complete file behind - never a half-written, truncated
        //                 config or block-list.
        //   (b) ELISION - if the target already holds exactly the bytes we would
        //                 write, the whole write is skipped. Hot config paths
        //                 (dnscrypt-proxy.toml, the single black/white lists) are
        //                 rewritten verbatim on every engine start; eliding the
        //                 unchanged ones spares needless NAND program/erase.
        //
        // Callers already hold reentrantLock and have restored target access, so
        // this stays a plain helper. Returns true on success, including an elided
        // no-op. Never a read-cache: reads here compare, they do not memoise.
        private fun atomicWriteLines(filePath: String, lines: List<String>): Boolean {
            // Exact bytes PrintWriter.println would emit: each line + '\n'
            // (System.lineSeparator() is "\n" on Android).
            val desired = StringBuilder().apply {
                for (line in lines) {
                    append(line).append('\n')
                }
            }.toString()

            val target = File(filePath)

            // (b) write-elision: bail out when on-disk bytes already match.
            if (target.isFile && target.canRead()) {
                try {
                    if (target.readText() == desired) {
                        logi("atomicWriteLines elide (unchanged) " + filePath)
                        return true
                    }
                } catch (e: Exception) {
                    // Elision is best-effort; a read failure just means we write.
                    logw("atomicWriteLines elision read failed " + filePath, e)
                }
            }

            // (a) atomic tmp + rename.
            val tmp = File(filePath + ".tmp")
            try {
                FileOutputStream(tmp).use { out ->
                    out.write(desired.toByteArray())
                    out.flush()
                    try {
                        out.fd.sync()
                    } catch (se: Exception) {
                        // Durability is a bonus; atomicity comes from the rename.
                        logw("atomicWriteLines fsync " + filePath, se)
                    }
                }

                // Match the target's expected posture: world-readable so a
                // same-uid native (dnscrypt-proxy) can read it after the swap.
                tmp.setReadable(true, false)
                tmp.setWritable(true)

                if (tmp.renameTo(target)) {
                    return true
                }

                // Rename can fail on a root-locked dir or a cross-device target.
                // Fall back to the legacy direct write so we never regress: a
                // torn file is worse than a non-atomic one, but a MISSING write
                // is worse than both.
                logw("atomicWriteLines rename failed, direct-writing " + filePath)
                PrintWriter(filePath).use { writer ->
                    for (line in lines) {
                        writer.println(line)
                    }
                }
                tmp.delete()
                return true
            } catch (e: Exception) {
                loge("atomicWriteLines " + filePath, e)
                tmp.delete()
                return false
            }
        }

        fun setOnFileOperationCompleteListener(callback: OnFileOperationsCompleteListener?) {
            if (stackCallbacks == null)
                stackCallbacks = CopyOnWriteArrayList()

            if (FileManager.callback != null)
                stackCallbacks!!.add(FileManager.callback!!)

            if (callback != null)
                FileManager.callback = callback
        }

        fun deleteOnFileOperationCompleteListener(callback: OnFileOperationsCompleteListener?) {
            if (stackCallbacks != null) {
                val lastIndexOfCallback = if (callback != null) stackCallbacks!!.lastIndexOf(callback) else -1

                if (stackCallbacks!!.isEmpty()) {
                    FileManager.callback = null
                } else if (callback === FileManager.callback) {
                    FileManager.callback = stackCallbacks!!.removeAt(stackCallbacks!!.size - 1)
                } else if (lastIndexOfCallback >= 0) {
                    stackCallbacks!!.removeAt(lastIndexOfCallback)
                }
            }
        }

        fun removeAllOnFileOperationsListeners() {
            if (callback != null)
                callback = null
            if (stackCallbacks != null && !stackCallbacks!!.isEmpty())
                stackCallbacks!!.clear()

            Thread {
                if (!executorService.isShutdown) {
                    executorService.shutdown()
                    try {
                        executorService.awaitTermination(10, TimeUnit.SECONDS)
                    } catch (e: InterruptedException) {
                        executorService.shutdownNow()
                        logw("FileOperations executorService awaitTermination has interrupted", e)
                    }

                }
            }.start()
        }
    }
}
