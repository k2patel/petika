//! Diagnostics against the provider's generated bindings, not custom declarations.
use std::ffi::CStr;

pub fn module_version() -> String {
    // SAFETY: the provider returns a process-lifetime, NUL-terminated static string.
    let version = unsafe { CStr::from_ptr(aws_lc_fips_sys::awslc_version_string()) };
    version.to_str().expect("ASCII provider version").to_owned()
}

#[cfg(test)]
pub fn approved<T>(operation: impl FnOnce() -> T) -> (T, bool) {
    // SAFETY: these no-argument APIs read thread-local counters. The synchronous
    // closure stays on this thread. Keep unrelated crypto outside this interval.
    let before = unsafe { aws_lc_fips_sys::FIPS_service_indicator_before_call() };
    let result = operation();
    let after = unsafe { aws_lc_fips_sys::FIPS_service_indicator_after_call() };
    (result, before != after)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_operation_is_not_reported_approved() {
        assert!(!approved(|| ()).1);
    }
}
