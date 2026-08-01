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

package pillar.kuma_saimono.libumdnscrypt.dns_engine.wire_cake_inu

import android.content.Context
import android.os.Build
import android.sun.security.x509.AlgorithmId
import android.sun.security.x509.CertificateAlgorithmId
import android.sun.security.x509.CertificateExtensions
import android.sun.security.x509.CertificateIssuerName
import android.sun.security.x509.CertificateSerialNumber
import android.sun.security.x509.CertificateSubjectName
import android.sun.security.x509.CertificateValidity
import android.sun.security.x509.CertificateVersion
import android.sun.security.x509.CertificateX509Key
import android.sun.security.x509.KeyIdentifier
import android.sun.security.x509.PrivateKeyUsageExtension
import android.sun.security.x509.SubjectKeyIdentifierExtension
import android.sun.security.x509.X500Name
import android.sun.security.x509.X509CertImpl
import android.sun.security.x509.X509CertInfo
import io.github.muntashirakon.adb.AbsAdbConnectionManager
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.Random

/**
 * The real Wave B engine: an [AbsAdbConnectionManager] that holds a persisted RSA key pair and a
 * self-signed certificate, so Yeah! Tortä can pair once (Android 11+ Wireless Debugging) and then
 * reconnect silently. Driven by [LibAdbElevation]; no PC, no root.
 */
class AdbConnectionManager private constructor(context: Context) : AbsAdbConnectionManager() {

    private val storedPrivateKey: PrivateKey
    private val storedCertificate: Certificate

    init {
        setApi(Build.VERSION.SDK_INT)

        val keyFile = File(context.filesDir, "adb_key")
        val certFile = File(context.filesDir, "adb_cert")

        var loadedKey: PrivateKey? = null
        var loadedCertificate: Certificate? = null

        if (keyFile.exists() && certFile.exists()) {
            try {
                loadedKey =
                    KeyFactory.getInstance("RSA")
                        .generatePrivate(PKCS8EncodedKeySpec(keyFile.readBytes()))
                loadedCertificate =
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(certFile.readBytes()))
            } catch (_: Exception) {
                loadedKey = null
                loadedCertificate = null
            }
        }

        if (loadedKey == null || loadedCertificate == null) {
            val (generatedKey, generatedCertificate) = generateKeyAndCertificate()
            storedPrivateKey = generatedKey
            storedCertificate = generatedCertificate
            keyFile.writeBytes(storedPrivateKey.encoded)
            certFile.writeBytes(storedCertificate.encoded)
        } else {
            storedPrivateKey = loadedKey
            storedCertificate = loadedCertificate
        }
    }

    private fun generateKeyAndCertificate(): Pair<PrivateKey, Certificate> {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(RSA_KEY_SIZE, SecureRandom.getInstance("SHA1PRNG"))
        val generatedKeyPair = keyPairGenerator.generateKeyPair()
        val publicKey: PublicKey = generatedKeyPair.getPublic()
        val newPrivateKey: PrivateKey = generatedKeyPair.getPrivate()

        val subject = "CN=Yeah! Torta"
        val algorithmName = "SHA512withRSA"
        val expiryDate =
            System.currentTimeMillis() + MILLIS_PER_DAY * DAYS_PER_YEAR * CERT_VALIDITY_YEARS

        val certificateExtensions = CertificateExtensions()
        certificateExtensions.set(
            "SubjectKeyIdentifier",
            SubjectKeyIdentifierExtension(KeyIdentifier(publicKey).identifier),
        )
        val x500Name = X500Name(subject)
        val notBefore = Date()
        val notAfter = Date(expiryDate)
        certificateExtensions.set("PrivateKeyUsage", PrivateKeyUsageExtension(notBefore, notAfter))
        val certificateValidity = CertificateValidity(notBefore, notAfter)
        val x509CertInfo = X509CertInfo()
        x509CertInfo.set("version", CertificateVersion(2))
        x509CertInfo.set(
            "serialNumber",
            CertificateSerialNumber(Random().nextInt() and Int.MAX_VALUE),
        )
        x509CertInfo.set("algorithmID", CertificateAlgorithmId(AlgorithmId.get(algorithmName)))
        x509CertInfo.set("subject", CertificateSubjectName(x500Name))
        x509CertInfo.set("key", CertificateX509Key(publicKey))
        x509CertInfo.set("validity", certificateValidity)
        x509CertInfo.set("issuer", CertificateIssuerName(x500Name))
        x509CertInfo.set("extensions", certificateExtensions)
        val x509CertImpl = X509CertImpl(x509CertInfo)
        x509CertImpl.sign(newPrivateKey, algorithmName)
        return newPrivateKey to x509CertImpl
    }

    protected override fun getPrivateKey(): PrivateKey = storedPrivateKey

    protected override fun getCertificate(): Certificate = storedCertificate

    protected override fun getDeviceName(): String = "YeahTorta"

    companion object {
        private const val RSA_KEY_SIZE = 2048
        private const val CERT_VALIDITY_YEARS = 10L
        private const val DAYS_PER_YEAR = 365L
        private const val MILLIS_PER_DAY = 86_400_000L

        @Volatile private var instance: AdbConnectionManager? = null

        @JvmStatic
        @Synchronized
        @Throws(Exception::class)
        fun getInstance(context: Context): AdbConnectionManager =
            instance ?: AdbConnectionManager(context.applicationContext).also { instance = it }
    }
}
