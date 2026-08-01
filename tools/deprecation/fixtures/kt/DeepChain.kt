package fixture

// EXPECT UNGATED: the gate is FOUR call levels above, and the walk is bounded at depth 3.
// Running out of budget must answer "not gated" -- an unfinished search is not evidence of safety.
// This fixture exists because a mutation that made depth-exhaustion absolve survived the corpus.
class DeepChain {
    private fun lvl4() {
        legacyCall()
    }

    private fun lvl3() {
        lvl4()
    }

    private fun lvl2() {
        lvl3()
    }

    private fun lvl1() {
        lvl2()
    }

    fun entry() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            lvl1()
        }
    }
}
