package fixture

// EXPECT UNGATED: the enclosing function has no discoverable call site. Unknown must never be
// absolved -- an unreferenced helper might be invoked reflectively or by the framework.
class NoCallers {
    private fun orphanHelper() {
        legacyCall()
    }
}
