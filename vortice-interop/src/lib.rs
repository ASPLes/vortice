// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Harness driving the LibVortex 1.1 regression suite.
//!
//! The suite is a client/listener pair of processes talking BEEP over a socket, which means
//! the two sides can be crossed: the Vortice client can be validated against
//! `vortex-regression-listener`, and a Vortice listener against `vortex-regression-client`.
//! This crate owns the process handling for both directions.
//!
//! It is not published; it exists so that conformance is checked in CI rather than by hand.
//!
//! # Locating the suite
//!
//! Set `VORTICE_LIBVORTEX_TEST_DIR` to the `test/` directory of a built LibVortex checkout:
//!
//! ```sh
//! export VORTICE_LIBVORTEX_TEST_DIR=~/programas/libvortex-1.1/test
//! ```
//!
//! When the variable is unset, [`LibVortex::from_env`] returns `None` and interop tests
//! report themselves as skipped instead of failing. Do not let CI treat that as a pass: a
//! job that is meant to check conformance must assert the suite was found.
//!
//! # Why the output is parsed rather than trusted
//!
//! `doc/regression-tests-map.md` in the LibVortex checkout documents two traps that make a
//! naive `status.success()` check meaningless, and [`ClientRun::check`] guards both:
//!
//! - an unrecognised `--run-test=` name matches nothing, runs no test at all, and still
//!   prints `INFO: All test ok!`;
//! - tests for modules the library was built without print `--- WARNING:` and return
//!   success, so a green run does not prove those areas were covered.
//!
//! There is a third trap, found while building this harness: the obvious defence against the
//! first one — checking that the requested test name shows up in the output — does not work
//! either, because the client echoes the name it was given in its `INFO: running test=…` and
//! `INFO: Checking to run test: …` banner lines before it has matched anything.
//!
//! That one has since been fixed upstream. `__run_test()` in `vortex-regression-client.c`
//! now brackets every test with machine readable markers keyed by the identifier
//! `--run-test` accepts, flushed so they survive a crash:
//!
//! ```text
//! INFO: [begin] test_01
//! Test 01: basic BEEP support [   OK   ] (finished in 0 secs, 2248 microseconds)
//! INFO: [end] test_01
//! ```
//!
//! [`ClientRun::completed`] uses those markers when present and falls back to parsing the
//! display-name completion line for LibVortex builds that predate them.

use std::env;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

mod lock;
pub mod profiles;

pub use lock::SuiteLock;

/// Environment variable naming the LibVortex `test/` directory.
pub const TEST_DIR_VAR: &str = "VORTICE_LIBVORTEX_TEST_DIR";

/// Base port the main regression listener binds, before any offset is applied.
pub const MAIN_LISTENER_PORT: u16 = 44010;

/// Base port the suite's WebSocket listener binds, before any offset is applied.
///
/// `test_17` opens its first connection here and then runs a whole run of ordinary tests
/// over it, so a listener on this port has to serve the full profile contract.
pub const WEBSOCKET_PORT: u16 = 44013;

/// Base port the suite's port-sharing listener binds, before any offset is applied.
///
/// `test_20` expects one port to take plain BEEP, BEEP over WebSocket and BEEP over
/// WebSocket over TLS, in that order.
pub const SHARING_PORT: u16 = 44015;

/// Environment variable overriding [`DEFAULT_PORT_OFFSET`].
pub const PORT_OFFSET_VAR: &str = "VORTICE_LIBVORTEX_PORT_OFFSET";

/// Offset added to every port the suite binds when nothing says otherwise.
///
/// It is deliberately not zero. The suite binds fixed ports, so a developer running it by
/// hand in another terminal — or a listener left behind by an earlier run — would otherwise
/// answer for the one these tests start, and the tests would silently exercise a process
/// nobody is tracking. Shifting by default keeps the two apart without anyone remembering to.
pub const DEFAULT_PORT_OFFSET: u16 = 1000;

/// How long [`Listener::wait_ready`] waits for the listener to accept connections.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Marker `__run_test()` prints before entering a test, followed by its identifier.
const BEGIN_MARKER: &str = "INFO: [begin] ";

/// Marker `__run_test()` prints after a test passes, followed by its identifier.
const END_MARKER: &str = "INFO: [end] ";

/// Marker `__run_test()` prints when a test fails, followed by its identifier.
const FAILED_MARKER: &str = "INFO: [failed] ";

/// Marker `run_test()` prints on the completion line of a test that passed.
const OK_MARKER: &str = "[   OK   ]";

/// Marker a test prints when it self-skips because its module is not built in.
const WARNING_MARKER: &str = "--- WARNING:";

/// Line the client prints when it finishes without a failure.
const SUCCESS_LINE: &str = "All test ok!";

/// A built LibVortex regression suite on disk.
#[derive(Debug, Clone)]
pub struct LibVortex {
    test_dir: PathBuf,
    port_offset: u16,
}

impl LibVortex {
    /// Locates the suite through [`TEST_DIR_VAR`], returning `None` when it is unset.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let test_dir = PathBuf::from(env::var_os(TEST_DIR_VAR)?);
        let port_offset = env::var(PORT_OFFSET_VAR)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_PORT_OFFSET);
        Some(Self {
            test_dir,
            port_offset,
        })
    }

    /// Uses an explicit `test/` directory.
    #[must_use]
    pub fn at(test_dir: impl Into<PathBuf>) -> Self {
        Self {
            test_dir: test_dir.into(),
            port_offset: DEFAULT_PORT_OFFSET,
        }
    }

    /// Uses a specific port offset instead of [`DEFAULT_PORT_OFFSET`].
    #[must_use]
    pub const fn with_port_offset(mut self, offset: u16) -> Self {
        self.port_offset = offset;
        self
    }

    /// The offset added to every port the suite binds.
    #[must_use]
    pub const fn port_offset(&self) -> u16 {
        self.port_offset
    }

    /// The port the main listener will bind, offset included.
    #[must_use]
    pub const fn listener_port(&self) -> u16 {
        MAIN_LISTENER_PORT + self.port_offset
    }

    /// The port the suite's WebSocket listener will bind, offset included.
    #[must_use]
    pub const fn websocket_port(&self) -> u16 {
        WEBSOCKET_PORT + self.port_offset
    }

    /// The port the suite's port-sharing listener will bind, offset included.
    #[must_use]
    pub const fn sharing_port(&self) -> u16 {
        SHARING_PORT + self.port_offset
    }

    /// The `test/` directory in use.
    #[must_use]
    pub fn test_dir(&self) -> &Path {
        &self.test_dir
    }

    /// Whether both regression binaries are present and executable.
    #[must_use]
    pub fn is_built(&self) -> bool {
        self.listener_binary().is_file() && self.client_binary().is_file()
    }

    /// Path of `vortex-regression-listener`.
    #[must_use]
    pub fn listener_binary(&self) -> PathBuf {
        self.test_dir.join("vortex-regression-listener")
    }

    /// Path of `vortex-regression-client`.
    #[must_use]
    pub fn client_binary(&self) -> PathBuf {
        self.test_dir.join("vortex-regression-client")
    }

    /// Starts `vortex-regression-listener` and waits until it accepts connections.
    ///
    /// The returned [`Listener`] kills the process when dropped, so a panicking test cannot
    /// leave a listener holding port [`MAIN_LISTENER_PORT`].
    ///
    /// # Errors
    ///
    /// Fails when the binary is missing, cannot be spawned, or does not accept a connection
    /// within [`READY_TIMEOUT`]. Fails too when [`MAIN_LISTENER_PORT`] is already taken:
    /// see [`LibVortex::port_is_free`] for why that matters more than it looks.
    pub fn start_listener(&self) -> io::Result<Listener> {
        let binary = self.listener_binary();
        if !binary.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found; build LibVortex first", binary.display()),
            ));
        }
        let port = self.listener_port();
        if !Self::port_is_free(port) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "port {port} is already taken; a stray vortex-regression-listener would \
                     silently answer for the one started here. Set {PORT_OFFSET_VAR} to move \
                     this run out of the way"
                ),
            ));
        }
        let child = Command::new(&binary)
            .arg(format!("--offset-port={}", self.port_offset))
            .current_dir(&self.test_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut listener = Listener { child };
        listener.wait_ready(port, READY_TIMEOUT)?;
        Ok(listener)
    }

    /// Whether nothing is currently listening on `port`.
    ///
    /// [`Listener::wait_ready`] cannot tell the listener it started from one that was
    /// already running: it polls until *something* accepts on the port. A stray listener
    /// left behind by an earlier run therefore answers for the one just spawned, which dies
    /// on a bind error, and every test then runs against a process nobody is tracking — with
    /// whatever build of LibVortex it happened to load when it started. That is not
    /// hypothetical: it is exactly what a listener left over from a previous session did
    /// here, quietly serving several supposedly clean runs. Checking the port beforehand
    /// turns that into an immediate, legible failure.
    #[must_use]
    pub fn port_is_free(port: u16) -> bool {
        std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_ok()
    }

    /// Runs `vortex-regression-client`, restricted to `tests` when it is not empty.
    ///
    /// Suite options are consumed positionally and only as the first argument, so at most
    /// one may be given; `--run-test=` accepts a comma separated list, which is how several
    /// tests are selected in one run.
    ///
    /// # Errors
    ///
    /// Fails when the binary is missing or cannot be spawned. A test *failing* is not an
    /// error here: it is reported through [`ClientRun::check`].
    pub fn run_client(&self, tests: &[&str]) -> io::Result<ClientRun> {
        let binary = self.client_binary();
        if !binary.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found; build LibVortex first", binary.display()),
            ));
        }
        let mut command = Command::new(&binary);
        command.current_dir(&self.test_dir);
        // The suite matches its options in a fixed order, with --offset-port first, so it
        // has to be passed before --run-test rather than after.
        command.arg(format!("--offset-port={}", self.port_offset));
        // Several tests assert on how long a transfer took, and those assertions say more
        // about how busy the machine is than about the listener: `test_02m` moves about 40 MB
        // and `test_04a` about 33 MB, and both have failed here purely from other tests
        // running alongside. Every protocol assertion still holds; only the stopwatch is
        // dropped. The suite offers this for exactly this reason — its own documentation
        // recommends it whenever the run is not alone on the machine.
        command.arg("--disable-time-checks");
        if !tests.is_empty() {
            command.arg(format!("--run-test={}", tests.join(",")));
        }
        let output = command.output()?;
        Ok(ClientRun::from_output(output))
    }
}

/// A running `vortex-regression-listener`, killed on drop.
#[derive(Debug)]
pub struct Listener {
    child: Child,
}

impl Listener {
    /// Waits until `port` accepts a TCP connection.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::TimedOut`] when the deadline passes without the port
    /// accepting, and propagates the child's exit if it died while being waited for.
    pub fn wait_ready(&mut self, port: u16, timeout: Duration) -> io::Result<()> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "regression listener exited before becoming ready: {status}"
                )));
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("regression listener did not open port {port} within {timeout:?}"),
                ));
            }
            sleep(Duration::from_millis(50));
        }
    }

    /// Kills the listener and reaps it.
    ///
    /// # Errors
    ///
    /// Propagates failures of the underlying kill or wait.
    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.child.try_wait()? {
            Some(_) => Ok(()),
            None => {
                self.child.kill()?;
                self.child.wait().map(|_| ())
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// The captured result of one `vortex-regression-client` run.
#[derive(Debug, Clone)]
pub struct ClientRun {
    /// Whether the process exited successfully.
    pub success: bool,
    /// Everything the client wrote to standard output.
    pub stdout: String,
    /// Everything the client wrote to standard error.
    pub stderr: String,
}

impl ClientRun {
    fn from_output(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Validates the run, defending against the ways the suite reports a false pass.
    ///
    /// Every name in `expected` must have completed, no `--- WARNING:` self-skip may be
    /// present, and the final `All test ok!` line must be there.
    ///
    /// # Errors
    ///
    /// Returns the first [`InteropError`] detected.
    pub fn check(&self, expected: &[&str]) -> Result<(), InteropError> {
        if !self.success {
            return Err(InteropError::ClientFailed {
                test: self.culprit(),
                output: self.transcript(),
            });
        }
        for name in expected {
            if !self.completed(name) {
                return Err(InteropError::TestNotRun {
                    name: (*name).to_owned(),
                    output: self.transcript(),
                });
            }
        }
        if let Some(line) = self
            .stdout
            .lines()
            .find(|line| line.contains(WARNING_MARKER))
        {
            return Err(InteropError::TestSkipped {
                line: line.trim().to_owned(),
            });
        }
        if !self.stdout.contains(SUCCESS_LINE) {
            return Err(InteropError::NoSuccessLine {
                output: self.transcript(),
            });
        }
        Ok(())
    }

    /// Whether a named test reported completion.
    ///
    /// Searching the output for the test name is *not* enough: the client echoes whatever
    /// was passed to `--run-test=` in its `INFO: running test=…` and
    /// `INFO: Checking to run test: …` banner lines, whether or not any test matches.
    ///
    /// A LibVortex build carrying the `INFO: [end] <name>` marker is believed directly. For
    /// builds without it, the fallback is the line `run_test()` prints when it returns,
    /// which is labelled with the test's display name rather than its identifier — see
    /// [`completion_label`]. Anchoring on the `<label>: ` prefix keeps `test_01` from being
    /// satisfied by `test_01a`.
    #[must_use]
    pub fn completed(&self, name: &str) -> bool {
        self.marked(END_MARKER, name) || self.completed_by_label(name)
    }

    /// Whether a named test reported failure through the `INFO: [failed] <name>` marker.
    #[must_use]
    pub fn failed(&self, name: &str) -> bool {
        self.marked(FAILED_MARKER, name)
    }

    /// The last test the client announced entering, if the markers are available.
    ///
    /// When a run dies without a verdict — a crash, a hang that was killed — this names the
    /// test that was in progress, which the `[begin]` marker is flushed to guarantee.
    #[must_use]
    pub fn last_started(&self) -> Option<&str> {
        self.stdout
            .lines()
            .filter_map(|line| line.strip_prefix(BEGIN_MARKER))
            .map(str::trim_end)
            .next_back()
    }

    /// The test a failed run should be blamed on: the one that reported failure, or failing
    /// that the one that was still in progress when the client died.
    fn culprit(&self) -> Option<String> {
        self.stdout
            .lines()
            .filter_map(|line| line.strip_prefix(FAILED_MARKER))
            .map(str::trim_end)
            .next_back()
            .or_else(|| self.last_started())
            .map(str::to_owned)
    }

    fn marked(&self, marker: &str, name: &str) -> bool {
        self.stdout
            .lines()
            .filter_map(|line| line.strip_prefix(marker))
            .any(|rest| rest.trim_end() == name)
    }

    /// Completion detection for LibVortex builds without the `[end]` marker.
    fn completed_by_label(&self, name: &str) -> bool {
        let label = completion_label(name);
        self.stdout.lines().any(|line| {
            let matches_prefix = |prefix: &str| {
                line.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(": ") && rest.contains(OK_MARKER))
            };
            matches_prefix(name) || label.as_deref().is_some_and(matches_prefix)
        })
    }

    fn transcript(&self) -> String {
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// The display name a test is labelled with on its completion line.
///
/// `run_test()` is called with a human readable label rather than the function name, so
/// `test_01` completes as `Test 01: basic BEEP support [   OK   ] (finished in …)`. The
/// mapping is mechanical — `test_` becomes `Test `, and any suffix after the two digit
/// number is separated with a hyphen — and was verified to hold for all 115 test names in
/// `vortex-regression-client.c` without exception:
///
/// ```
/// use vortice_interop::completion_label;
///
/// assert_eq!(completion_label("test_01").as_deref(), Some("Test 01"));
/// assert_eq!(completion_label("test_01g1").as_deref(), Some("Test 01-g1"));
/// assert_eq!(completion_label("test_001").as_deref(), Some("Test 00-1"));
/// assert_eq!(completion_label("not-a-test"), None);
/// ```
#[must_use]
pub fn completion_label(name: &str) -> Option<String> {
    let rest = name.strip_prefix("test_")?;
    if rest.len() < 2 {
        return None;
    }
    let (number, suffix) = rest.split_at(2);
    Some(if suffix.is_empty() {
        format!("Test {number}")
    } else {
        format!("Test {number}-{suffix}")
    })
}

/// Why an interop run was not accepted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InteropError {
    /// The regression client exited with a failure status.
    ClientFailed {
        /// The test that reported failure, or the one in progress when the client died.
        test: Option<String>,
        /// Captured output, for the assertion message.
        output: String,
    },
    /// A requested test name never appeared in the output.
    ///
    /// The suite silently ignores an unknown `--run-test=` name and still reports success,
    /// so this is the check that distinguishes "passed" from "never ran".
    TestNotRun {
        /// The test that did not run.
        name: String,
        /// Captured output, for the assertion message.
        output: String,
    },
    /// A test self-skipped because LibVortex was built without the module it covers.
    TestSkipped {
        /// The warning line emitted by the suite.
        line: String,
    },
    /// The run finished without the suite's success line.
    NoSuccessLine {
        /// Captured output, for the assertion message.
        output: String,
    },
}

impl fmt::Display for InteropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientFailed {
                test: Some(test),
                output,
            } => write!(f, "vortex-regression-client failed in {test}\n{output}"),
            Self::ClientFailed { test: None, output } => {
                write!(f, "vortex-regression-client exited with failure\n{output}")
            }
            Self::TestNotRun { name, output } => write!(
                f,
                "test '{name}' never ran: the suite ignores unknown --run-test names \
                 and still reports success\n{output}"
            ),
            Self::TestSkipped { line } => write!(
                f,
                "a test self-skipped because the module is not built into LibVortex: {line}"
            ),
            Self::NoSuccessLine { output } => {
                write!(f, "run finished without the 'All test ok!' line\n{output}")
            }
        }
    }
}

impl std::error::Error for InteropError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(stdout: &str, success: bool) -> ClientRun {
        ClientRun {
            success,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// A completion line in the exact shape `run_test()` prints.
    fn completion(name: &str) -> String {
        let label = completion_label(name).unwrap_or_else(|| name.to_owned());
        format!("{label}: some description [   OK   ] (finished in 0 secs, 1000 microseconds)\n")
    }

    #[test]
    fn recognises_the_completion_line_libvortex_actually_prints() {
        // Verbatim from a real `--run-test=test_01` run: the completion line is labelled
        // "Test 01", not "test_01".
        let output = "INFO: running test=test_01\n\
                      INFO: Checking to run test: test_01..\n\
                      Test 01: basic BEEP support [   OK   ] (finished in 0 secs, 1978 microseconds)\n\
                      **\n** INFO: All test ok!\n**\n";
        assert!(run(output, true).check(&["test_01"]).is_ok());
    }

    #[test]
    fn accepts_a_clean_run() {
        let output = format!("{}INFO: All test ok!\n", completion("test_01"));
        assert!(run(&output, true).check(&["test_01"]).is_ok());
    }

    #[test]
    fn rejects_a_test_that_never_ran() {
        // The trap: an unknown --run-test name runs nothing and still reports success.
        let output = "INFO: All test ok!\n";
        assert!(matches!(
            run(output, true).check(&["test_typo"]),
            Err(InteropError::TestNotRun { .. })
        ));
    }

    #[test]
    fn believes_the_machine_readable_markers() {
        // Verbatim from a real `--run-test=test_01,test_02b` run against a client carrying
        // the [begin]/[end] markers.
        let output = "INFO: [begin] test_01\n\
                      Test 01: basic BEEP support [   OK   ] (finished in 0 secs, 2248 microseconds)\n\
                      INFO: [end] test_01\n\
                      INFO: [begin] test_02b\n\
                      Test 02-b: small message followed by close [   OK   ] (finished in 0 secs, 502489 microseconds)\n\
                      INFO: [end] test_02b\n\
                      ** INFO: All test ok!\n";
        let result = run(output, true);
        assert!(result.check(&["test_01", "test_02b"]).is_ok());
        assert_eq!(result.last_started(), Some("test_02b"));
    }

    #[test]
    fn does_not_accept_a_test_that_only_began() {
        // A test that started and never reported an end did not pass.
        let output = "INFO: [begin] test_01\n** INFO: All test ok!\n";
        assert!(matches!(
            run(output, true).check(&["test_01"]),
            Err(InteropError::TestNotRun { .. })
        ));
    }

    #[test]
    fn names_the_test_a_failed_run_should_be_blamed_on() {
        let output = "INFO: [begin] test_02n\n\
                      Test 02-n: msgno reuse [ FAILED ]\n\
                      INFO: [failed] test_02n\n";
        let result = run(output, false);
        assert!(result.failed("test_02n"));
        assert!(
            matches!(result.check(&[]), Err(InteropError::ClientFailed { test: Some(name), .. }) if name == "test_02n")
        );
    }

    #[test]
    fn blames_the_test_in_progress_when_the_client_dies_without_a_verdict() {
        // The [begin] marker is flushed precisely so a crash still identifies the test.
        let output = "INFO: [begin] test_01g1\n";
        let result = run(output, false);
        assert!(
            matches!(result.check(&[]), Err(InteropError::ClientFailed { test: Some(name), .. }) if name == "test_01g1")
        );
    }

    #[test]
    fn is_not_fooled_by_the_name_echoed_in_the_banner() {
        // What the client actually prints for --run-test=test_does_not_exist: the name
        // appears twice, no test runs, and the success line is printed anyway.
        let output = "INFO: running test=test_does_not_exist\n\
                      INFO: Checking to run test: test_does_not_exist..\n\
                      **\n** INFO: All test ok!\n**\n";
        assert!(matches!(
            run(output, true).check(&["test_does_not_exist"]),
            Err(InteropError::TestNotRun { .. })
        ));
    }

    #[test]
    fn does_not_accept_a_longer_test_name_in_place_of_the_one_requested() {
        // test_01a completing must not be read as test_01 completing.
        let output = format!("{}INFO: All test ok!\n", completion("test_01a"));
        let result = run(&output, true);
        assert!(result.completed("test_01a"));
        assert!(!result.completed("test_01"));
    }

    #[test]
    fn rejects_a_self_skipped_module() {
        let output = "--- WARNING: TLS not enabled, skipping test\nINFO: All test ok!\n";
        assert!(matches!(
            run(output, true).check(&[]),
            Err(InteropError::TestSkipped { .. })
        ));
    }

    #[test]
    fn rejects_a_run_without_the_success_line() {
        assert!(matches!(
            run(&completion("test_01"), true).check(&["test_01"]),
            Err(InteropError::NoSuccessLine { .. })
        ));
    }

    #[test]
    fn rejects_a_failing_process() {
        assert!(matches!(
            run("INFO: All test ok!\n", false).check(&[]),
            Err(InteropError::ClientFailed { .. })
        ));
    }

    #[test]
    fn reports_a_missing_suite_rather_than_guessing() {
        let suite = LibVortex::at("/nonexistent/test");
        assert!(!suite.is_built());
        assert_eq!(
            suite.start_listener().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
