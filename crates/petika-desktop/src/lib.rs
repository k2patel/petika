//! Future Chromium/Firefox native messaging and OS authentication integration.
//! No native messaging host or biometric authentication is implemented yet.

/// Reports overall project status; this crate does not implement native platform support.
pub fn status() -> &'static str {
    petika_core::STATUS
}
