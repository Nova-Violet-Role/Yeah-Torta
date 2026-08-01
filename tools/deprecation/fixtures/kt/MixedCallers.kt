package fixture

// EXPECT UNGATED: two call sites, one gated and one not. `sites.every` must reject.
// This is the ModulesReceiver shape -- a try/catch fallback reaching the legacy path on a modern
// device -- and it is the case my manual reading got wrong before the tool corrected me.
class MixedCallers {
    private fun mixedHelper() {
        legacyCall()
    }

    fun gatedEntry() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            mixedHelper()
        }
    }

    fun ungatedEntry() {
        mixedHelper()
    }
}
