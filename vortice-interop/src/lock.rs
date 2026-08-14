// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Keeping the interop tests from running at the same time as each other.
//!
//! There are three of them now — plain TCP, WebSocket and TLS — each starting a listener and
//! driving a `vortex-regression-client` through multi-megabyte transfers. They live in
//! different crates, so cargo builds and runs their binaries **concurrently**, and three C
//! clients moving tens of megabytes at once is enough to make the suite's own timing-sensitive
//! tests fail: `test_02m` moves about 40 MB and has failed exactly this way.
//!
//! Distinct ports are not the answer, because the contention is processor and disk rather than
//! addresses, and a mutex is not the answer either, because these are separate processes.
//! What is left is a lock the operating system arbitrates.
//!
//! `create_dir` is used as that lock: creating a directory is atomic on every platform this
//! runs on, succeeding for exactly one caller. A lock file with a flag inside would not be —
//! checking and then writing is two steps with a gap in the middle.

use std::fs;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

/// How long to wait between attempts.
const RETRY: Duration = Duration::from_millis(200);

/// After this, a lock is assumed to belong to a process that died holding it.
///
/// Generous on purpose: the whole point is to serialise runs that take minutes, so the cost of
/// waiting too long is a slow test run, while the cost of stealing too early is two suites
/// interfering and a failure that looks like a protocol bug. The second is far more expensive.
const STALE_AFTER: Duration = Duration::from_secs(15 * 60);

/// Held for as long as one interop test is running.
///
/// Released on drop, including when a test panics, since unwinding runs destructors. A process
/// killed outright leaves it behind, which is what [`STALE_AFTER`] is for.
#[derive(Debug)]
pub struct SuiteLock {
    path: PathBuf,
}

impl SuiteLock {
    /// Waits until no other interop test is running, then claims that right.
    ///
    /// ```no_run
    /// # use vortice_interop::SuiteLock;
    /// let _lock = SuiteLock::acquire();
    /// // the suite is ours until `_lock` goes out of scope
    /// ```
    ///
    /// Take it before binding a port or starting a listener, and hold it for the whole test.
    #[must_use]
    pub fn acquire() -> Self {
        Self::acquire_at(std::env::temp_dir().join("vortice-interop-suite.lock"))
    }

    /// As [`SuiteLock::acquire`], on a named lock. Private: one suite, one lock.
    fn acquire_at(path: PathBuf) -> Self {
        loop {
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if is_stale(&path) {
                        eprintln!(
                            "vortice-interop: breaking a lock left behind at {}",
                            path.display()
                        );
                        let _ = fs::remove_dir(&path);
                    }
                    sleep(RETRY);
                }
                Err(error) => {
                    // Nothing to serialise against if the lock cannot be created at all —
                    // better a run that races than one that cannot start.
                    eprintln!("vortice-interop: could not take the suite lock: {error}");
                    return Self { path };
                }
            }
        }
    }
}

impl Drop for SuiteLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

/// Whether a lock has been held longer than any real run would take.
fn is_stale(path: &PathBuf) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        // It went away between the failed create and this call, which is not stale, just lost.
        return false;
    };
    let Ok(created) = metadata.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(created)
        .is_ok_and(|age| age > STALE_AFTER)
}

#[cfg(test)]
mod tests {
    use super::SuiteLock;

    /// A lock of its own for each test: these run concurrently in one binary, and sharing the
    /// real one would have them wait for each other and then assert about each other's state.
    fn own_lock(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("vortice-interop-{name}.lock"));
        let _ = std::fs::remove_dir(&path);
        path
    }

    #[test]
    fn a_lock_is_released_when_it_is_dropped() {
        let path = own_lock("dropped");

        let lock = SuiteLock::acquire_at(path.clone());
        assert!(path.is_dir(), "holding the lock should create it");

        drop(lock);
        assert!(!path.exists(), "dropping it should release it");
    }

    #[test]
    fn a_lock_is_released_when_the_holder_panics() {
        let path = own_lock("panicking");
        let taken = path.clone();

        let outcome = std::panic::catch_unwind(move || {
            let _lock = SuiteLock::acquire_at(taken);
            panic!("as a test that fails would");
        });

        assert!(outcome.is_err(), "the panic should have been caught");
        assert!(
            !path.exists(),
            "a test that fails must not leave the lock behind for everything after it"
        );
    }
}
