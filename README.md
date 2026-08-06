# vortice

BEEP implementation for Rust.

Vortice implements BEEP (RFC3080/RFC3081) for Rust. It is developed by Advanced Software
Production Line (ASPL) maintainers of [LibVortex 1.1](https://github.com/ASPLes/libvortex-1.1)

## Documentation

- [`doc/design-decisions.md`](doc/design-decisions.md) — architecture and API design, with rationale
- [`doc/development-plan.md`](doc/development-plan.md) — phased plan with exit criteria
- [`doc/http-port-sharing.md`](doc/http-port-sharing.md) — running BEEP and HTTP on the same port

## Crates

| Crate | Contents |
|---|---|
| `vortice-proto` | Sans-IO core: framing, greetings, channel management, flow control and the session state machine. `no_std` + `alloc`, no `unsafe` |
| `vortice-interop` | Test harness driving the LibVortex regression suite. Not published |

More crates are added as their phase in the development plan arrives.

## Build and test

```sh
cargo test                      # unit tests and doctests
cargo clippy --all-targets      # warnings are errors in CI
```

Conformance is checked against a built [LibVortex 1.1](https://github.com/ASPLes/libvortex-1.1)
checkout, whose regression suite is the oracle for this project:

```sh
export VORTICE_LIBVORTEX_TEST_DIR=/path/to/libvortex-1.1/test
cargo test
```

Without that variable the interop tests report themselves as skipped rather than failing.
Do not read a skipped run as a passing one.

The regression suite binds fixed ports, so these tests shift them by 1000 through the
suite's own `--offset-port` option. That keeps them clear of a suite someone is running by
hand on the default ports, and of any listener an earlier run left behind. Set
`VORTICE_LIBVORTEX_PORT_OFFSET` to move them somewhere else.

Fuzzing the frame decoder and the greeting parser (needs nightly and `cargo-fuzz`):

```sh
cd vortice-proto/fuzz
cargo +nightly fuzz run decode_frames
```
