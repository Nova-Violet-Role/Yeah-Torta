package fixture

// EXPECT UNGATED -- the safety twin of FarEnclosingGate, and the reason the new rule is sound
// rather than merely more generous. The SDK_INT block has CLOSED before this call, so the call
// runs on every device. A rule that simply looked further up would absolve it; enclosure by brace
// depth refuses to, because a closed block can never be an enclosing opener.
class AfterGateCloses {
    fun check() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            modernOne()
        } else {
            modernTwo()
        }
        legacyCall()
    }
}
