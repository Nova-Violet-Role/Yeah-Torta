package fixture

// EXPECT gated: the SDK_INT test is within the 15-line window directly above the call.
class DirectGate {
    fun doWork() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            modernPath()
        } else {
            legacyCall()
        }
    }
}
