package fixture

// EXPECT gated: the helper has NO gate of its own; its ONLY call site is inside an SDK_INT branch.
// This is the shape depclass v1 got wrong and v2 exists to handle.
class CallerGate {
    private fun legacyHelper() {
        legacyCall()
    }

    fun entry() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            legacyHelper()
        }
    }
}
