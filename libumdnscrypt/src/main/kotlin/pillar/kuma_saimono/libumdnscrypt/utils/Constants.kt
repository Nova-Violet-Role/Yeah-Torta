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

package pillar.kuma_saimono.libumdnscrypt.utils

import androidx.annotation.Keep

@Keep
object Constants {
    const val LOOPBACK_ADDRESS = "127.0.0.1"
    const val LOOPBACK_ADDRESS_IPv6 = "::1"
    const val META_ADDRESS = "0.0.0.0"
    const val META_ADDRESS_IPv6 = "::"
    const val MAX_PORT_NUMBER = 65535
    const val STANDARD_WIFI_INTERFACE_NAME = "wlan0"
    const val STANDARD_ETHERNET_INTERFACE_NAME = "eth0"
    const val STANDARD_VPN_INTERFACE_NAME = "tun0"
    const val STANDARD_USB_MODEM_INTERFACE_NAME = "rndis0"
    const val STANDARD_AP_INTERFACE_RANGE = "192.168.43."
    const val EXTENDED_AP_INTERFACE_RANGE = "192.168."
    const val STANDARD_USB_MODEM_INTERFACE_RANGE = "192.168.42."
    const val STANDARD_VPN_ADDRESS = "10.1.10.1"
    const val STANDARD_ADDRESS_LOCAL_PC = "192.168.0.100"

    @JvmField
    val STANDARD_ETHERNET_INTERFACE_NAMES = arrayOf("eth+")

    @JvmField
    val STANDARD_WIFI_INTERFACE_NAMES = arrayOf("wlan+", "swlan+", "tiwlan+", "ra+", "bnep+")

    @JvmField
    val STANDARD_3G_INTERFACE_NAMES = arrayOf(
        "rmnet+", "pdp+", "uwbr+", "wimax+", "vsnet+",
        "rmnet_sdio+", "ccmni+", "qmi+", "svnet0+", "ccemni+",
        "wwan+", "cdma_rmnet+", "clat4+", "cc2mni+", "bond1+", "rmnet_smux+", "ccinet+",
        "v4-rmnet+", "seth_w+", "v4-rmnet_data+", "rmnet_ipa+", "rmnet_data+", "r_rmnet_data+"
    )

    @JvmField
    val STANDARD_USB_INTERFACE_TETHER_NAMES = arrayOf("bt-pan", "usb+", "rndis+", "rmnet_usb+")

    const val HTTP_PORT = 80

    const val DEFAULT_PROXY_PORT = "1080"

    const val DNS_OVER_TLS_PORT = 853

    const val PLAINTEXT_DNS_PORT = 53

    const val ROOT_DEFAULT_UID = 0
    const val DNS_DEFAULT_UID = 1051
    const val NETWORK_STACK_DEFAULT_UID = 1073

    const val VPN_DNS_2 = "89.233.43.71" //blog.uncensoreddns.org

    const val G_DNG_41 = "8.8.8.8"
    const val G_DNS_42 = "8.8.4.4"
    const val G_DNS_61 = "2001:4860:4860::8888"
    const val G_DNS_62 = "2001:4860:4860::8844"
    const val DNS_GOOGLE = "https://dns.google"
    const val DNS_QUAD9 = "https://dns9.quad9.net"
    const val DNS_MOZILLA = "https://mozilla.cloudflare-dns.com"

    const val QUAD_DNS_41 = "9.9.9.9"
    const val QUAD_DNS_42 = "149.112.112.112"
    const val QUAD_DNS_61 = "2620:fe::fe"
    const val QUAD_DNS_62 = "2620:fe::9"

    const val C_DNS_41 = "1.1.1.1"
    const val C_DNS_42 = "1.0.0.1"
    const val C_DNS_61 = "2606:4700:4700::1111"
    const val C_DNS_62 = "2606:4700:4700::1001"

    const val QUAD_DOH_SERVER = "https://dns.quad9.net/dns-query"

    //https://datatracker.ietf.org/doc/html/rfc6762
    const val LAN_DOMAIN_ENDINGS = ".local, .lan, .home, .corp, .private, .internal, .intranet, .254.169.in-addr.arpa, .8.e.f.ip6.arpa, .9.e.f.ip6.arpa, .a.e.f.ip6.arpa, .b.e.f.ip6.arpa"

    const val CHROME_BROWSER_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36"

    const val DNSCRYPT_RESOLVERS_SOURCE_IPV6 = "https://ipv6.download.dnscrypt.info/resolvers-list/v3/public-resolvers.md"
    const val DNSCRYPT_RELAYS_SOURCE_IPV6 = "https://ipv6.download.dnscrypt.info/resolvers-list/v3/relays.md"

    // dnscrypt-proxy upstream release feed — binary version awareness only (check-and-notify, NO in-app download)
    const val DNSCRYPT_PROXY_RELEASES_API = "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"
    // dnscrypt-proxy RELEASE minisign key (distinct from the resolver-list key) — reserved for a future verified binary fetch
    const val DNSCRYPT_PROXY_MINISIGN_RELEASE_KEY = "RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5"

    const val DEFAULT_SITES_IPS_REFRESH_INTERVAL = 12

    const val NFLOG_GROUP = 78
    const val NFLOG_PREFIX = "IPRO:LOG"

    const val IPv4_REGEX = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"
    const val IPv4_REGEX_NO_BOUNDS = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"

    const val IPv4_REGEX_WITH_MASK = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])(?:\\.(?:[01]?\\d\\d?|2[0-4]\\d|25[0-5])){3}(?:/[0-2]\\d|/3[0-2])?$"

    const val IPv4_REGEX_WITH_PORT = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\\d+)$"

    const val IPv6_REGEX = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    const val IPv6_REGEX_NO_CAPTURING = "(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
    const val IPv6_REGEX_NO_BOUNDS = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    const val IPv6_REGEX_WITH_MASK = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$"

    const val NUMBER_REGEX = "\\d+"

    const val HOST_NAME_REGEX = "[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,63}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)"
    const val URL_REGEX = "(https?:\\/\\/)?(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,63}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)"
}
