package fixture

// EXPECT gated: the SDK_INT test is on an OUTER enclosing block, with an unrelated `if` between it
// and the call. The scan must keep walking outward past the innermost enclosing block rather than
// stopping at the first one it meets -- a mutation that replaced the outward `continue` with a
// `break` survived the corpus until this fixture existed.
class NestedGate {
    fun check(flag: Boolean) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            if (flag) {
                legacyCall()
            }
        }
    }
}
