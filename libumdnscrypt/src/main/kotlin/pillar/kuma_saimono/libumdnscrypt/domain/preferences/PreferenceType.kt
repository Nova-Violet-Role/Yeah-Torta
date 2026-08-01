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

package pillar.kuma_saimono.libumdnscrypt.domain.preferences

import androidx.annotation.IntDef

@IntDef(
    PreferenceType.BOOL_PREFERENCE,
    PreferenceType.INT_PREFERENCE,
    PreferenceType.FLOAT_PREFERENCE,
    PreferenceType.STRING_PREFERENCE,
    PreferenceType.STRING_SET_PREFERENCE
)
@Retention(AnnotationRetention.SOURCE)
annotation class PreferenceType {
    companion object {
        const val BOOL_PREFERENCE = 1
        const val INT_PREFERENCE = 2
        const val FLOAT_PREFERENCE = 3
        const val STRING_PREFERENCE = 4
        const val STRING_SET_PREFERENCE = 5
    }
}
