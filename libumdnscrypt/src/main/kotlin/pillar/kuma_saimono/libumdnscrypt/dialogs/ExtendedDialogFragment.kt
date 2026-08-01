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

package pillar.kuma_saimono.libumdnscrypt.dialogs

import android.app.Dialog
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.FragmentManager
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.logw

abstract class ExtendedDialogFragment : DialogFragment() {

    @JvmField
    var handler: Handler? = null

    private var waitForOpenCounter = 2
    private var waitForCloseCounter = 3

    /**
     * Mirrors the value this class writes to the deprecated `retainInstance`.
     *
     * `onDestroyView` needs to know whether the instance is retained, and READING
     * `retainInstance` is a second deprecated usage on top of the write. Since this class is the
     * only thing in the repository that ever writes it -- measured by repo-wide grep, which found
     * exactly two occurrences, the write below and the read in `onDestroyView` -- the value can be
     * mirrored where it is set instead of read back from the deprecated property.
     *
     * WHY A FIELD AND NOT JUST `true`: this is a LIBRARY module and the class is `abstract` and
     * public, so a subclass outside this repository may override `onCreate` and never call
     * `super`. In that case `retainInstance` stays false -- and so does this mirror. The two agree
     * in BOTH cases, which is what makes the substitution exact rather than merely usually right.
     * Hard-coding `true` would have been a constant condition that silently changed behaviour for
     * a caller I cannot see.
     */
    private var retainedByThisFragment = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // No non-deprecated equivalent: `setRetainInstance` was deprecated in Fragment 1.3 in
        // favour of a ViewModel, which is a different mechanism with different lifetime, not a
        // drop-in. Kept, and narrowed to this single write.
        @Suppress("DEPRECATION")
        run { retainInstance = true }
        retainedByThisFragment = true

        handler = Handler(Looper.getMainLooper())
    }

    //Considering the use
    private fun blurBackground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (dialog == null) {
                return
            }
            val activity = dialog!!.ownerActivity
            if (activity == null) {
                return
            }
            activity.window.decorView.rootView
                .setRenderEffect(
                    RenderEffect.createBlurEffect(
                        5f,
                        5f,
                        Shader.TileMode.CLAMP
                    )
                )
        }
    }

    private fun unblurBackground() {
        if (dialog == null) {
            return
        }
        val activity = dialog!!.ownerActivity
        if (activity == null) {
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            activity.window.decorView.rootView
                .setRenderEffect(null)
        }
    }

    override fun onDestroyView() {
        val dialog = dialog
        // handles https://code.google.com/p/android/issues/detail?id=17423
        // The guard reads [retainedByThisFragment] rather than the deprecated `retainInstance`;
        // the two are written together in onCreate and are equal in every reachable state,
        // including a subclass outside this module that never calls super.onCreate.
        if (dialog != null && retainedByThisFragment) {
            dialog.setDismissMessage(null)
        }

        super.onDestroyView()
    }

    override fun onDestroy() {

        if (handler != null) {
            handler!!.removeCallbacksAndMessages(null)
        }

        super.onDestroy()
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val builder = assignBuilder()
        return if (builder != null) {
            builder.create()
        } else {
            loge("ExtendedDialogFragment fault: please assignBuilder first")
            super.onCreateDialog(savedInstanceState)
        }
    }

    override fun show(manager: FragmentManager, tag: String?) {
        try {
            showDialog(manager, tag)
        } catch (e: IllegalStateException) {
            logw("ExtendedDialogFragment show", e)

            if (handler == null) {
                handler = Handler(Looper.getMainLooper())
            }

            waitForOpenCounter--
            if (waitForOpenCounter > 0) {
                handler!!.post {
                    try {
                        showDialog(manager, tag)
                    } catch (ex: Exception) {
                        logw("ExtendedDialogFragment show", ex)
                    }
                }
            } else if (waitForOpenCounter == 0) {
                handler!!.postDelayed({
                    try {
                        showDialog(manager, tag)
                    } catch (ex: Exception) {
                        logw("ExtendedDialogFragment show", ex)
                    }
                }, 500L)
            }
        } catch (e: WindowManager.BadTokenException) {
            logw("ExtendedDialogFragment show", e)

            if (handler == null) {
                handler = Handler(Looper.getMainLooper())
            }

            waitForOpenCounter--
            if (waitForOpenCounter > 0) {
                handler!!.post {
                    try {
                        showDialog(manager, tag)
                    } catch (ex: Exception) {
                        logw("ExtendedDialogFragment show", ex)
                    }
                }
            } else if (waitForOpenCounter == 0) {
                handler!!.postDelayed({
                    try {
                        showDialog(manager, tag)
                    } catch (ex: Exception) {
                        logw("ExtendedDialogFragment show", ex)
                    }
                }, 500L)
            }
        }
    }

    private fun showDialog(manager: FragmentManager, tag: String?) {
        if (manager.isDestroyed) {
            return
        }
        manager.executePendingTransactions()
        val fragment = manager.findFragmentByTag(tag)
        if (fragment == null || !fragment.isAdded) {
            val ft = manager.beginTransaction()
            ft.add(this, tag)
            ft.commitAllowingStateLoss()
        }
    }

    override fun dismiss() {
        if (isStateSaved) {
            if (waitForCloseCounter > 0 && handler != null) {
                handler!!.postDelayed({ dismiss() }, 100L)
                waitForCloseCounter--
            } else {
                super.dismissAllowingStateLoss()
            }
        } else {
            super.dismiss()
        }
    }

    abstract fun assignBuilder(): AlertDialog.Builder?
}
