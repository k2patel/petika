//! Future Chromium/Firefox native messaging and OS authentication integration.
//! No native messaging host or biometric authentication is implemented yet.

/// Reports the foundation status without claiming platform support.
pub fn status() -> &'static str {
    petika_core::STATUS
}
