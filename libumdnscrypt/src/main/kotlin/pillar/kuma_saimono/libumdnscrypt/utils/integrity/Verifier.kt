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

package pillar.kuma_saimono.libumdnscrypt.utils.integrity

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import dalvik.system.ZipPathValidator
import pillar.kuma_saimono.libumdnscrypt.R
import pillar.kuma_saimono.libumdnscrypt.TopFragmentState
import pillar.kuma_saimono.libumdnscrypt.settings.PathVars
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logi
import java.io.BufferedWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Locale
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class Verifier @Inject constructor(
    val context: Context,
    val pathVars: dagger.Lazy<PathVars>
) {

    @Volatile
    private var apkSignature: String? = null

    @Throws(Exception::class)
    private fun getApkSignatureZip(): String {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ZipPathValidator.clearCallback()
        }

        val apkFile = File(context.applicationInfo.sourceDir)

        val zipFile = ZipFile(apkFile)
        val entries = zipFile.entries()
        while (entries.hasMoreElements()) {
            val ze = entries.nextElement()
            val name = ze.name.uppercase(Locale.getDefault())
            if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA"))) {
                try {
                    zipFile.getInputStream(ze).use { inputStream ->
                        ByteArrayOutputStream().use { baos ->
                            val buffer = ByteArray(8192)
                            var len: Int
                            while (inputStream.read(buffer).also { len = it } != -1) {
                                baos.write(buffer, 0, len)
                            }
                            var byteSign = baos.toByteArray()
                            byteSign = CertificateFactory.getInstance("X509").generateCertificate(ByteArrayInputStream(byteSign)).encoded
                            return Base64.encodeToString(MessageDigest.getInstance("md5").digest(byteSign), Base64.DEFAULT)
                        }
                    }
                } finally {
                    zipFile.close()
                }
            }
        }

        loge("Verifier unable to get signature from zip. Use the conventional method instead.")

        return getApkSignature()
    }

    @Suppress("unused")
    @Throws(Exception::class)
    private fun getApkSignatureZipModern(): String? {
        val apkFile = File(context.applicationInfo.sourceDir)
        val zipFile = ZipFile(apkFile)
        val ze = zipFile.getEntry("META-INF/CERT.RSA") ?: return null
        val inputStream = zipFile.getInputStream(ze)
        val baos = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var len: Int
        while (inputStream.read(buffer).also { len = it } != -1) {
            baos.write(buffer, 0, len)
        }
        baos.close()
        inputStream.close()
        zipFile.close()
        var byteSign = baos.toByteArray()
        byteSign = CertificateFactory.getInstance("X509").generateCertificate(ByteArrayInputStream(byteSign)).encoded
        return Base64.encodeToString(MessageDigest.getInstance("md5").digest(byteSign), Base64.DEFAULT)
    }


    //The arguement is your public key's value that is deal with md5 and base64
    @SuppressLint("PackageManagerGetSignatures")
    @Throws(Exception::class)
    fun getApkSignature(): String {
        val packageManager = this.context.packageManager
        val strPackagename = this.context.packageName

        val signatureArray = packageManager.getPackageInfo(strPackagename, PackageManager.GET_SIGNATURES).signatures

        var byteSign = signatureArray!![0].toByteArray()
        byteSign = CertificateFactory.getInstance("X509").generateCertificate(ByteArrayInputStream(byteSign)).encoded
        //String strSign = new String(Base64.encode(MessageDigest.getInstance("md5").digest(byteSign), 19));
        return Base64.encodeToString(MessageDigest.getInstance("md5").digest(byteSign), Base64.DEFAULT)
    }

    @Throws(Exception::class)
    fun decryptStr(text: String, key: String, vector: String): String {
        var innerKey = key
        innerKey = innerKey.substring(innerKey.length - 16)
        // Create key and cipher
        val aesKey: Key = SecretKeySpec(innerKey.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        // decrypt the text
        val ivBytes = vector.substring(vector.length - 16).toByteArray()
        cipher.init(Cipher.DECRYPT_MODE, aesKey, IvParameterSpec(ivBytes))
        val decrypted = Base64.decode(text.toByteArray(StandardCharsets.UTF_8), Base64.DEFAULT)
        if (pathVars.get().appVersion.endsWith("d")) {
            return String(decrypted)
        }
        return String(cipher.doFinal(decrypted))
    }

    fun encryptStr(text: String, key: String, vector: String) {

        try {
            if (TopFragmentState.debug) {
                var innerKey = key
                innerKey = innerKey.substring(innerKey.length - 16)
                // Create key and cipher
                val aesKey: Key = SecretKeySpec(innerKey.toByteArray(), "AES")

                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                val ivBytes = vector.substring(vector.length - 16).toByteArray()
                // encrypt the text
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, IvParameterSpec(ivBytes))
                val encrypted = cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8))

                val f = File(pathVars.get().appDataDir + "/logs")

                if (f.mkdirs() && f.setReadable(true) && f.setWritable(true)) {
                    logi("encryptStr log dir created")
                } else {
                    loge("encryptStr Unable to create and chmod log dir")
                }

                val writer = PrintWriter(
                    BufferedWriter(
                        FileWriter(
                            pathVars.get().appDataDir + "/logs/EncryptedStr.txt", true
                        )
                    )
                )
                writer.println(text)
                writer.println(Base64.encodeToString(encrypted, Base64.DEFAULT))
                writer.println("********************")
                writer.close()
            }


        } catch (e: Exception) {
            loge("encryptStr Failed", e)
        }
    }

    fun getWrongSign(): String {
        return context.getString(R.string.encoded).trim { it <= ' ' }
    }

    @Throws(Exception::class)
    fun getAppSignature(): String {
        if (apkSignature == null) {
            synchronized(Verifier::class.java) {
                if (apkSignature == null) {
                    apkSignature = getApkSignatureZip()
                }
            }
        }
        return apkSignature!!
    }

}
