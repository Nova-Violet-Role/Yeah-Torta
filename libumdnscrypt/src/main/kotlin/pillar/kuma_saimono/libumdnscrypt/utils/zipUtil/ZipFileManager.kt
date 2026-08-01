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

package pillar.kuma_saimono.libumdnscrypt.utils.zipUtil

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import dalvik.system.ZipPathValidator
import pillar.kuma_saimono.libumdnscrypt.utils.filemanager.FileManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Objects
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class ZipFileManager @JvmOverloads constructor(private val zipFile: String? = null) {

    @Throws(Exception::class)
    fun extractZipFromInputStream(inputStream: InputStream, outputPathDir: String) {
        val outputFile = File(removeEndSlash(outputPathDir))

        if (!outputFile.isDirectory) {
            if (!outputFile.mkdir()) {
                throw IllegalStateException("ZipFileManager cannot create output dir " + outputPathDir)
            }
        }

        ZipInputStream(inputStream).use { zipInputStream ->

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ZipPathValidator.clearCallback()
            }

            var zipEntry = zipInputStream.nextEntry

            while (zipEntry != null) {

                if (zipEntry.isDirectory) {
                    val fileName = zipEntry.name
                    val fileFullName = File(outputPathDir + "/" + removeEndSlash(fileName))

                    if (!fileFullName.isDirectory) {
                        if (!fileFullName.mkdirs()) {
                            throw IllegalStateException("ZipFileManager cannot create output dirs structure: dir " + fileFullName.absolutePath)
                        }
                    }
                } else {
                    val fileName = zipEntry.name
                    val fileFullName = File(outputPathDir + "/" + removeEndSlash(fileName))
                    val fileParent = File(removeEndSlash(Objects.requireNonNull(fileFullName.parent)))

                    if (!fileParent.isDirectory) {
                        if (!fileParent.mkdirs()) {
                            throw IllegalStateException("ZipFileManager cannot create output dirs structure: dir " + fileParent.absolutePath)
                        }
                    }

                    FileOutputStream(fileFullName).use { outputStream ->
                        copyData(zipInputStream, outputStream)
                    }
                }

                zipEntry = zipInputStream.nextEntry
            }
        }
    }

    @Throws(Exception::class)
    fun extractZip(outputPathDir: String) {
        // `zipFile` is nullable because of the @JvmOverloads no-arg constructor. Extracting without
        // a path is a programming error, so it is named as one HERE instead of surfacing three
        // frames deeper as a bare NPE from the File(String) constructor.
        val inputFile = File(requireNotNull(zipFile) { "extractZip on a ZipFileManager built without a zip path" })

        if (!inputFile.exists()) {
            throw FileNotFoundException("ZipFileManager input file missing " + zipFile)
        }

        FileInputStream(inputFile).use { inputStream ->
            extractZipFromInputStream(inputStream, outputPathDir)
        }

    }

    @Throws(Exception::class)
    fun createZip(context: Context, vararg inputSource: String) {
        val inputSources = ArrayList<File>()
        for (source in inputSource) {
            inputSources.add(File(source))
        }

        val outputFile = File(requireNotNull(zipFile) { "createZip on a ZipFileManager built without a zip path" })
        val outputFileDir = File(removeEndSlash(Objects.requireNonNull(outputFile.parent)))

        if (!outputFileDir.isDirectory) {
            if (outputFileDir.mkdirs()) {
                throw IllegalStateException("ZipFileManager cannot create output dir " + outputFileDir.absolutePath)
            }
        }

        ZipOutputStream(FileOutputStream(zipFile)).use { zipOutputStream ->
            for (inputFile in inputSources) {
                addZipEntry(context, zipOutputStream, removeEndSlash(Objects.requireNonNull(inputFile.parent)), inputFile.name)
            }
        }
    }

    @Throws(Exception::class)
    private fun addZipEntry(context: Context, zipOutputStream: ZipOutputStream, inputPath: String, fileName: String) {

        val fullPath = inputPath + "/" + fileName

        checkAndRestoreAccess(context, fullPath)

        val inputFile = File(fullPath)
        if (inputFile.isDirectory) {

            val files = inputFile.listFiles()

            if (files != null) {
                for (file in files) {
                    val nextFileName = file.absolutePath.replace(inputPath + "/", "")
                    addZipEntry(context, zipOutputStream, inputPath, nextFileName)
                }
            }
        } else if (inputFile.isFile) {
            FileInputStream(fullPath).use { inputStream ->
                val zipEntry = ZipEntry(fileName)
                zipOutputStream.putNextEntry(zipEntry)
                copyData(inputStream, zipOutputStream)
                zipOutputStream.closeEntry()
            }
        } else {
            throw IllegalStateException("createZip input fault: input no file and no dir " + fullPath)
        }
    }

    @Throws(Exception::class)
    private fun copyData(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(8 * 1024)
        var len: Int
        while (input.read(buffer).also { len = it } > 0) {
            output.write(buffer, 0, len)
        }
    }

    private fun removeEndSlash(path: String): String {
        var result = path
        if (result.trim { it <= ' ' }.endsWith("/")) {
            result = result.substring(0, result.lastIndexOf("/"))
        }
        return result
    }

    @SuppressLint("SetWorldReadable")
    private fun checkAndRestoreAccess(context: Context, path: String) {
        var f: File? = null

        try {
            f = File(path)
        } catch (e: Exception) {
            logw("ZipFileManager File is no accessible " + e.message + " " + e.cause + " .Try to restore access.")
            val fileManager = FileManager()
            fileManager.restoreAccess(context, path)
        }

        if (f == null) {
            throw IllegalStateException("ZipFileManager File is no accessible " + path)
        }

        if (f.isFile && !f.canRead()) {
            if (f.setReadable(true, false)) {
                logi("ZipFileManager take " + path + " success")
            } else {
                logw("ZipFileManager take " + path + " warning")
                val fileManager = FileManager()
                fileManager.restoreAccess(context, path)
                if (f.setReadable(true, false)) {
                    logi("ZipFileManager take " + path + " success")
                } else {
                    throw IllegalStateException("ZipFileManager File is no accessible " + path + " error")
                }
            }
        }
    }
}
