//! The capability query must tell the truth in BOTH directions.
//!
//! This file exists because the opposite was shipped: a build with no forwarder compiled in
//! reported the pillar as armed, because the claim came from a preference instead of from the
//! binary. A test that only checked the `netstack` build would have passed on the broken one.
#[test]
fn the_capability_query_matches_the_features_this_binary_was_built_with() {
    let compiled = torta_core::tunnel_netstack_compiled();
    let expected = cfg!(all(unix, feature = "netstack"));
    assert_eq!(
        compiled, expected,
        "tunnel_netstack_compiled() must mirror cfg!(all(unix, feature = \"netstack\")) EXACTLY; \
         it is the only thing standing between a user and a UI that claims a forwarder which was \
         never built"
    );
}

/// The pairing rule stated as a test rather than a comment: a UI may only claim ARMED when the
/// user asked for it AND this binary can actually do it.
#[test]
fn armed_implies_compiled_for_every_combination_of_preference_and_capability() {
    fn armed(wants: bool, can: bool) -> bool {
        wants && can
    }
    for wants in [false, true] {
        for can in [false, true] {
            if armed(wants, can) {
                assert!(
                    can,
                    "armed was reported while the capability was absent (wants={wants}, can={can})"
                );
            }
        }
    }
    assert!(
        !armed(true, false),
        "a preference alone must never render as ARMED"
    );
}

/// The feature half, which is testable on EVERY host -- unlike the conjunction above, whose
/// `unix` term is false on a Windows developer machine and therefore hid a surviving mutant.
#[test]
fn the_feature_query_matches_the_cargo_feature_on_any_platform() {
    assert_eq!(
        torta_core::tunnel_netstack_feature_enabled(),
        cfg!(feature = "netstack"),
        "tunnel_netstack_feature_enabled() must report the cargo feature exactly, on every \
         platform -- this is the half of the capability that a Windows host can still police"
    );
}

/// The conjunction may never claim MORE than the feature allows. Stated as a law rather than as
/// two separate observations, so it holds for whatever platform term is added next.
#[test]
fn compiled_never_exceeds_the_feature() {
    if torta_core::tunnel_netstack_compiled() {
        assert!(
            torta_core::tunnel_netstack_feature_enabled(),
            "the capability claimed to be compiled while the feature that provides the code was \
             not enabled -- the conjunction has drifted from its own terms"
        );
    }
}
