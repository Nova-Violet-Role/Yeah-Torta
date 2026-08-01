package fixture

// EXPECT gated: the call sits in the `else` of an SDK_INT test whose `if` is TWENTY lines above.
// The old 15-line window missed it, so NetworkChecker.kt:159 was reported as backlog while its
// IDENTICAL twin ten lines higher was reported as gated -- two verdicts for the same expression,
// decided by line spacing. Enclosure, not distance, is the question.
class FarEnclosingGate {
    fun check() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            modernOne()
            modernTwo()
            modernThree()
            modernFour()
            modernFive()
            modernSix()
            modernSeven()
            modernEight()
            modernNine()
            modernTen()
            modernEleven()
            modernTwelve()
            modernThirteen()
            modernFourteen()
            modernFifteen()
            modernSixteen()
        } else {
            legacyCall()
        }
    }
}
