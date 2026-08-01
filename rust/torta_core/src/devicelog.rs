//! ★ THE DIAGNOSTICS WERE GOING NOWHERE.
//!
//! `torta_core` logs through the `log` facade (`log::{error, warn}` — e.g.
//! `forwarder/upstream.rs:147` prints the destination of every failed protected dial). The facade
//! DISCARDS everything until a logger is installed, and nothing ever installed one. Measured
//! consequence: 597 upstream dials failed with `ECONNREFUSED` on device while `logcat` contained
//! ZERO Tortä lines, so the one datum that identifies the refusing destination — already computed,
//! already formatted — was thrown away at the facade.
//!
//! A diagnostic that reaches nowhere is decoration, exactly as an instrument that cannot fail is.
//! This module is the sink that makes those calls real, with no new dependency: a `log::Log` over
//! Android's `__android_log_write`.

/// Install the process-wide logger ONCE. Idempotent and infallible by construction: a second call
/// (or a caller that has already installed a logger) is a no-op, never a panic — installing a log
/// sink must never be able to take the engine down.
pub(crate) fn init_device_logging() {
    #[cfg(target_os = "android")]
    android::install();
}

#[cfg(target_os = "android")]
mod android {
    use libc::c_char;
    use std::ffi::CString;

    // Android's liblog. Priorities are the NDK's `android_LogPriority`:
    // 2=VERBOSE 3=DEBUG 4=INFO 5=WARN 6=ERROR.
    extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }

    const TAG: &str = "torta_core";

    struct DeviceLog;

    impl log::Log for DeviceLog {
        fn enabled(&self, _m: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let prio = match record.level() {
                log::Level::Error => 6,
                log::Level::Warn => 5,
                log::Level::Info => 4,
                log::Level::Debug => 3,
                log::Level::Trace => 2,
            };
            // A NUL inside a formatted message must drop THAT line, never abort the process --
            // logging is never allowed to be fatal.
            let Ok(tag) = CString::new(TAG) else { return };
            let Ok(msg) = CString::new(format!("{}", record.args())) else {
                return;
            };
            // SAFETY: both pointers are NUL-terminated and live for the duration of the call;
            // liblog copies the text and retains neither.
            unsafe {
                __android_log_write(prio, tag.as_ptr(), msg.as_ptr());
            }
        }

        fn flush(&self) {}
    }

    static SINK: DeviceLog = DeviceLog;

    pub(super) fn install() {
        // `set_logger` fails only if one is already installed -- which is a success for us.
        if log::set_logger(&SINK).is_ok() {
            log::set_max_level(log::LevelFilter::Debug);
        }
    }
}
