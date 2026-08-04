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
| `vortice-proto` | Sans-IO core: BEEP framing, greetings. `no_std` + `alloc`, no `unsafe` |
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
cargo test -p vortice-interop -- --test-threads=1
```

Without that variable the interop tests report themselves as skipped rather than failing.
Do not read a skipped run as a passing one.

Fuzzing the frame decoder and the greeting parser (needs nightly and `cargo-fuzz`):

```sh
cd vortice-proto/fuzz
cargo +nightly fuzz run decode_frames
```
