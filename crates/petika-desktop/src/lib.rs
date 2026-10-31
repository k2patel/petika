//! Native integration candidates. Product native messaging and biometric custody
//! are not implemented yet; experimental transport coordination requires a custodian.

#[cfg(all(feature = "experimental-git-client", not(target_arch = "wasm32")))]
pub mod git_lease;

/// Reports overall project status; product platform authentication remains pending.
pub fn status() -> &'static str {
    petika_core::STATUS
}
