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

import android.content.Intent
import android.os.Build
import java.io.Serializable

/**
 * `Intent.getSerializableExtra(String)` is deprecated since API 33 (TIRAMISU) in favour of the
 * type-checked `getSerializableExtra(String, Class<T>)`. This module's minSdkVersion is 21
 * (`build.gradle:67`), so the new overload cannot simply replace the old one -- it does not exist
 * on most of the range this app supports. The branch is the fix; there is no flag that removes it.
 *
 * ## Why this is one helper and not eight `if (SDK_INT >= 33)` blocks
 * There were eight call sites. Eight copies of a version branch is eight chances to get the bound
 * wrong, and the failure mode is invisible: the legacy branch keeps working on the CI emulator, so
 * a mistake in the modern branch is only felt by users on new phones.
 *
 * ## The @Suppress below is NOT hiding dead code
 * It is scoped to the single expression that MUST call the deprecated overload, because that is the
 * only API available below 33. It suppresses a warning about a call that is correct and required,
 * which is the one legitimate use of the annotation. It is not applied to the file or the class,
 * so anything else that goes stale in here still shouts.
 *
 * ## On the unchecked cast
 * `getSerializableExtra(name, T::class.java)` verifies the class at the boundary on API 33+; below
 * that, the runtime returns `Serializable` and only `as? T` can be applied -- which for a generic
 * `T` erases. Both paths therefore return null rather than throwing when the extra is of the wrong
 * type: `as?` on the legacy path, and the platform's own class check on the modern one. A caller
 * that gets null must treat it as "absent", which is what an Intent extra always could be.
 */
inline fun <reified T : Serializable> Intent.serializableExtraCompat(name: String): T? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getSerializableExtra(name, T::class.java)
    } else {
        @Suppress("DEPRECATION")
        getSerializableExtra(name) as? T
    }

/**
 * The same bridge for a serialized `ArrayList<String>` payload -- the tethering interface list.
 *
 * A separate function because the reified helper above cannot express it: `List<String>` is not
 * statically `Serializable`, and the concrete class that actually crosses the Binder is
 * `ArrayList`. Asking the platform for `ArrayList::class.java` on API 33+ is what makes the modern
 * path a REAL check rather than a cast dressed as one.
 *
 * Returns null when the extra is absent or is not a list, so a caller cannot mistake "no tethering
 * information" for "tethering is off" -- those are different, and the caller decides which.
 */
fun Intent.stringListExtraCompat(name: String): List<String>? {
    val raw: Serializable? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            getSerializableExtra(name, ArrayList::class.java)
        } else {
            @Suppress("DEPRECATION")
            getSerializableExtra(name)
        }
    if (raw !is List<*>) return null
    // Element-wise, because erasure means the container check above says nothing about contents.
    // filterIsInstance rather than a blanket cast: a list carrying one non-String would otherwise
    // throw at an unrelated call site later, naming a class instead of the intent extra at fault.
    return raw.filterIsInstance<String>().takeIf { it.size == raw.size }
}
