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

@file:JvmName("ProxyFragmentKt")

package pillar.kuma_saimono.libumdnscrypt.proxy

/**
 * Preference key for the app-set that bypasses the proxy (clearnet apps). This used to live as a
 * top-level constant inside the retired ProxyFragment UI, but it is read by the load-bearing VPN
 * datapath (vpn/Rule.java, vpn/service/VpnPreferenceHolder.kt), so it migrates here unchanged.
 * The @file:JvmName keeps the Java call site (ProxyFragmentKt.CLEARNET_APPS_FOR_PROXY) resolving.
 */
const val CLEARNET_APPS_FOR_PROXY = "clearnetAppsForProxy"
