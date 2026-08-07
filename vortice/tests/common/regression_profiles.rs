// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! The subset of the LibVortex regression listener contract Vortice serves.
//!
//! Shared by the integration test and by `examples/regression-listener.rs` so the two cannot
//! drift: what CI verifies is exactly what a developer gets when running the example by hand.
//!
//! Two profiles are deliberately absent. The suite's `/deny` is not registered at all,
//! because `test_02` requires a start for it to fail on the grounds that the profile is
//! unknown — a different code from one that is registered and refuses. And
//! `/ans-nul-reply-close` needs a connection-accepted hook, which Vortice does not have yet.

#![allow(dead_code, unreachable_pub)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vortice::{AlwaysRefuse, Message, Responder, Router, SessionId, code};

const ECHO: &str = "http://iana.org/beep/transient/vortex-regression";
const ECHO_2: &str = "http://iana.org/beep/transient/vortex-regression/2";
const ECHO_3: &str = "http://iana.org/beep/transient/vortex-regression/3";
const DENY_SUPPORTED: &str = "http://iana.org/beep/transient/vortex-regression/deny_supported";

/// Reply, then close the channel from this end — so the two `<close>` messages cross.
const CLOSE_IN_TRANSIT: &str = "http://iana.org/beep/transient/close-in-transit";

/// Bulk one-to-many transfer: the request names how much to send.
const BLOCKS: &str = "http://iana.org/beep/transient/vortex-regression/4";

/// One-to-many transfer of a file the request names, relative to the working directory.
const FILES: &str = "http://iana.org/beep/transient/vortex-regression/5";

/// How much of a file goes into each answer.
const FILE_BLOCK: usize = 4096;

const SIMPLE_ANS_NUL: &str = "http://iana.org/beep/transient/vortex-regression/simple-ans-nul";
const ANS_NUL_WAIT: &str = "http://iana.org/beep/transient/vortex-regression/ans-nul-wait";
const MIXING_REPLIES: &str = "http://iana.org/beep/transient/vortex-regression/mixing-replies";
const CLOSE_AFTER_ANS_NUL: &str =
    "http://iana.org/beep/transient/vortex-regression/close-after-ans-nul-replies";

/// How many answers `/simple-ans-nul` sends before its `NUL`.
const SIMPLE_ANS_COUNT: usize = 30;

/// How many answers `/close-after-ans-nul-replies` sends before closing.
const CLOSE_AFTER_ANS_COUNT: usize = 10_000;

/// The exact 4096 octet payload the suite expects back, `TEST_REGRESION_URI_4_MESSAGE`.
///
/// The content matters: `test_02m` compares what it receives against this byte for byte, so
/// filler of the right length would not do. It is 75 repetitions of a 54 octet sentence
/// followed by a 46 octet tail.
fn bulk_payload() -> bytes::Bytes {
    const UNIT: &str = "This is a large file that contains arbitrary content. ";
    const TAIL: &str = "This is a large file that contains arbitrary .";

    let mut payload = String::with_capacity(4096);
    for _ in 0..75 {
        payload.push_str(UNIT);
    }
    payload.push_str(TAIL);
    debug_assert_eq!(payload.len(), 4096);
    bytes::Bytes::from(payload)
}

/// The profiles this listener serves.
#[must_use]
pub fn regression_router() -> Router {
    let echo = |responder: Responder, message: Message| async move {
        if std::env::var_os("VORTICE_TRACE").is_some() {
            eprintln!(
                "[msg] channel={} msgno={} len={}",
                responder.channel(),
                message.msgno,
                message.payload.len()
            );
        }
        let _ = responder.reply(message.msgno, message.payload).await;
    };
    // /mixing-replies alternates between reply shapes per connection, so it needs somewhere
    // to remember which one is next. A handler is shared by every session serving it, hence
    // the key on SessionId.
    let mixing: Arc<Mutex<HashMap<SessionId, bool>>> = Arc::new(Mutex::new(HashMap::new()));

    Router::new()
        .profile(ECHO, echo)
        .profile(
            BLOCKS,
            |responder: Responder, message: Message| async move {
                // The request is `<anything>,<block size>,<block count>`: send that many answers
                // of that many octets, then the NUL that ends the transfer.
                let request = String::from_utf8_lossy(&message.payload).into_owned();
                let mut fields = request.split(',').skip(1);
                let block_size: usize = fields
                    .next()
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let block_count: usize = fields
                    .next()
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);

                let block = bulk_payload().slice(..block_size.min(4096));
                for _ in 0..block_count {
                    if responder
                        .answer(message.msgno, block.clone())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = responder.finish(message.msgno).await;
            },
        )
        .profile(FILES, |responder: Responder, message: Message| async move {
            let request = String::from_utf8_lossy(&message.payload).into_owned();

            // A request to shrink frames to the path MTU. Vortice paces against the window
            // rather than the segment size, so there is nothing to tune; the peer only needs
            // its acknowledgement.
            if request == "change-mss" {
                let _ = responder.reply(message.msgno, message.payload).await;
                return;
            }

            let Ok(contents) = tokio::fs::read(&request).await else {
                let _ = responder
                    .error(message.msgno, "Unable to open file requested")
                    .await;
                return;
            };

            let contents = bytes::Bytes::from(contents);
            for start in (0..contents.len()).step_by(FILE_BLOCK) {
                let end = (start + FILE_BLOCK).min(contents.len());
                if responder
                    .answer(message.msgno, contents.slice(start..end))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = responder.finish(message.msgno).await;
        })
        .profile(
            SIMPLE_ANS_NUL,
            |responder: Responder, message: Message| async move {
                // The suite drives the receiving window from the wire before starting.
                if let Some(size) = message.payload.strip_prefix(b"window_size=") {
                    let size = core::str::from_utf8(size)
                        .ok()
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(4096);
                    let _ = responder.set_window_size(size).await;
                    let _ = responder.reply(message.msgno, "ok").await;
                    return;
                }
                for _ in 0..SIMPLE_ANS_COUNT {
                    let _ = responder
                        .answer(message.msgno, message.payload.clone())
                        .await;
                }
                let _ = responder.finish(message.msgno).await;
            },
        )
        .profile(
            ANS_NUL_WAIT,
            |responder: Responder, message: Message| async move {
                for (index, text) in [
                    "this is a test..",
                    "this is a test..2",
                    "this is a test..3",
                    "this is a test..3",
                ]
                .into_iter()
                .enumerate()
                {
                    let _ = responder.answer(message.msgno, text).await;
                    // The C profile waits between answers on purpose, to make sure a peer
                    // that is not ready for a slow one-to-many reply shows it.
                    let millis = 130 + 10 * u64::try_from(index).unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
                }
                let _ = responder.finish(message.msgno).await;
            },
        )
        .profile(
            MIXING_REPLIES,
            move |responder: Responder, message: Message| {
                let mixing = Arc::clone(&mixing);
                async move {
                    let use_rpy = {
                        let mut state = mixing.lock().unwrap_or_else(|e| e.into_inner());
                        let flag = state.entry(responder.session()).or_insert(false);
                        let current = *flag;
                        *flag = !current;
                        current
                    };
                    if use_rpy {
                        let _ = responder.reply(message.msgno, "a reply").await;
                    } else {
                        let _ = responder.answer(message.msgno, "a reply 1").await;
                        let _ = responder.answer(message.msgno, "a reply 2").await;
                        let _ = responder.finish(message.msgno).await;
                    }
                }
            },
        )
        .profile(
            CLOSE_AFTER_ANS_NUL,
            |responder: Responder, message: Message| async move {
                let payload = bulk_payload();
                for _ in 0..CLOSE_AFTER_ANS_COUNT {
                    if responder
                        .answer(message.msgno, payload.clone())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = responder.finish(message.msgno).await;
                let _ = responder.close().await;
            },
        )
        .profile(
            CLOSE_IN_TRANSIT,
            |responder: Responder, message: Message| async move {
                let _ = responder.reply(message.msgno, message.payload).await;
                let _ = responder.close().await;
            },
        )
        .profile(ECHO_2, echo)
        // /3 answers and then starts three exchanges of its own, so the peer can reply to
        // them in whatever order it likes. Sending all three concurrently is the point: a
        // serialised sender would never give the peer the chance.
        .profile(
            ECHO_3,
            |responder: Responder, message: Message| async move {
                let _ = responder.reply(message.msgno, "").await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let _ = tokio::join!(
                    responder.request("MSG###1###"),
                    responder.request("MSG###2###"),
                    responder.request("MSG###3###"),
                );
            },
        )
        .profile(
            DENY_SUPPORTED,
            AlwaysRefuse::with_text(code::SERVICE_NOT_AVAILABLE, "channel refused on purpose"),
        )
}
