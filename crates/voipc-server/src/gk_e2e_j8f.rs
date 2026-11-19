//! End-to-end group-key scenarios added by fix-round slice J8F (2026-11-19). The relay's real
//! `gk` code driven by the clients' real `voipc_crypto::group_state` code; shared helpers live in
//! `gk_e2e_tests.rs`.

/// T1e E's other half: a kept copy filed after its epoch's window for a chain start closed
/// (accounts/log.rs `chain_start`: the head, or the one before for `HOLD_MS`) is filed again
/// under the head the app holds, not lost (`group_state::Copies` offers it again, K1 lets it
/// go only after the relay refused it as gone). The scenario runs on `gk_e2e_t1`'s world.
#[tokio::test]
async fn e2e_j8f_a_kept_copy_filed_after_its_epochs_window_is_kept_under_the_head() {
    super::gk_e2e_t1::a_copy_filed_after_its_epochs_window_is_kept_under_the_head().await;
}
