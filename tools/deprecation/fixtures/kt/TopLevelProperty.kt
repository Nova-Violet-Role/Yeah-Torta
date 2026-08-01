package fixture

// EXPECT UNGATED: a property initialiser is evaluated at class-init on every device and sits
// inside no function at all, so there is no caller that could be gated. This is the exact shape
// of ModulesReceiver's five LEGACY_* constants.
class TopLevelProperty {
    companion object {
        private val LEGACY_CONST: String = legacyCall()
    }
}
