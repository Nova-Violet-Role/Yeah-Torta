package fixture

// EXPECT UNGATED: mutual recursion. The `seen` set must break the cycle and return false rather
// than looping forever or concluding "gated" from an unfinished walk.
class Cycle {
    private fun ping() {
        legacyCall()
        pong()
    }

    private fun pong() {
        ping()
    }
}
