package fixture

// EXPECT gated: the statement is inside setup(), which gates it. An anonymous object declared
// ABOVE it contains an `override fun` that is nested DEEPER, and a naive upward scan would return
// that override instead -- whose callers are the framework's and therefore invisible, collapsing
// the verdict to UNGATED. The indentation test in enclosingFun is what prevents that, and this
// fixture exists because a mutation removing it survived the corpus.
class AnonObject {
    fun setup() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            register(object : Callback() {
                override fun onEvent() {
                    doNothing()
                }
            })
            legacyCall()
        }
    }
}
