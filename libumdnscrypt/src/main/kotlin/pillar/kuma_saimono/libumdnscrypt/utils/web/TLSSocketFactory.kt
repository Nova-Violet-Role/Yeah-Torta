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

package pillar.kuma_saimono.libumdnscrypt.utils.web

import android.content.Context
import pillar.kuma_saimono.libumdnscrypt.R
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class TLSSocketFactory
@Throws(
    KeyManagementException::class,
    NoSuchAlgorithmException::class,
    CertificateException::class,
    KeyStoreException::class,
    IOException::class
)
constructor(private val appContext: Context) : SSLSocketFactory() {

    private val delegate: SSLSocketFactory

    init {
        val context = SSLContext.getInstance("TLS")
        context.init(null, getTrustManagerFactory().trustManagers, null)
        delegate = context.socketFactory
    }

    override fun getDefaultCipherSuites(): Array<String> {
        return delegate.defaultCipherSuites
    }

    override fun getSupportedCipherSuites(): Array<String> {
        return delegate.supportedCipherSuites
    }

    @Throws(IOException::class)
    override fun createSocket(): Socket {
        return enableTLSOnSocket(delegate.createSocket())
    }

    @Throws(IOException::class)
    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
        return enableTLSOnSocket(delegate.createSocket(s, host, port, autoClose))
    }

    @Throws(IOException::class)
    override fun createSocket(host: String, port: Int): Socket {
        return enableTLSOnSocket(delegate.createSocket(host, port))
    }

    @Throws(IOException::class)
    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
        return enableTLSOnSocket(delegate.createSocket(host, port, localHost, localPort))
    }

    @Throws(IOException::class)
    override fun createSocket(host: InetAddress, port: Int): Socket {
        return enableTLSOnSocket(delegate.createSocket(host, port))
    }

    @Throws(IOException::class)
    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
        return enableTLSOnSocket(delegate.createSocket(address, port, localAddress, localPort))
    }

    private fun enableTLSOnSocket(socket: Socket): Socket {
        if (socket is SSLSocket) {
            socket.enabledProtocols = arrayOf("TLSv1.1", "TLSv1.2")
        }
        return socket
    }

    @Throws(
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        IOException::class,
        CertificateException::class
    )
    fun getTrustManagerFactory(): TrustManagerFactory {

        val cf = CertificateFactory.getInstance("X.509")
        val isgCertificateX1: Certificate = cf.generateCertificate(appContext.resources.openRawResource(R.raw.isrg_root_x1))
        val isgCertificateX2: Certificate = cf.generateCertificate(appContext.resources.openRawResource(R.raw.isrg_root_x2))

        // Create a KeyStore containing our trusted CAs
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(null, null)
        keyStore.setCertificateEntry("isrg_root_x1", isgCertificateX1)
        keyStore.setCertificateEntry("isrg_root_x2", isgCertificateX2)

        //Default TrustManager to get device trusted CA
        val defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        defaultTmf.init(null as KeyStore?)

        val trustManager = defaultTmf.trustManagers[0] as X509TrustManager
        var number = 0
        for (cert in trustManager.acceptedIssuers) {
            keyStore.setCertificateEntry(number.toString(), cert)
            number++
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)

        return tmf
    }
}
