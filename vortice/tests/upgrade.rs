// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Replacing the transport of a live session.
//!
//! This is the hook BEEP's TLS is built on, tested without TLS so that what is being checked
//! is the mechanism rather than a library. The stand-in transport does two things a real one
//! does: it performs a handshake with an ordering (the initiator speaks first, the listener
//! answers), and it transforms every octet afterwards. The second is what proves the session
//! really moved onto the replacement — a swap that quietly kept using the old transport would
//! pass every other assertion here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use vortice::{
    BoxedTransport, Config, Connection, Error, Handler, HandlerFuture, Message, Profile, Responder,
    Role, Router, Server, Start,
};

/// The profile whose reply is the signal to swap, standing in for the TLS profile.
const UPGRADE: &str = "urn:example:upgrade";

/// Served before and after, to show the session still works over the new transport.
const ECHO: &str = "urn:example:echo";

/// Advertised only in the greeting that follows the swap.
const AFTER: &str = "urn:example:after-upgrade";

/// What the stand-in transport scrambles every octet with.
const KEY: u8 = 0x5a;

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("operation timed out")
}

/// A transport that scrambles what passes through it.
///
/// Not encryption and not pretending to be: it is the cheapest possible transformation that
/// makes traffic unreadable to the layer below, which is all this test needs from it.
struct Scrambled<T> {
    inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for Scrambled<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                for octet in &mut buf.filled_mut()[before..] {
                    *octet ^= KEY;
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Scrambled<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let scrambled: Vec<u8> = buf.iter().map(|octet| octet ^ KEY).collect();
        Pin::new(&mut self.inner).poll_write(cx, &scrambled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The initiator's half of the stand-in handshake: speak, then listen.
async fn client_swap(mut io: BoxedTransport) -> vortice::Result<BoxedTransport> {
    io.write_all(b"\x01").await?;
    io.flush().await?;
    let mut answer = [0u8; 1];
    io.read_exact(&mut answer).await?;
    assert_eq!(answer, [0x02], "the listener should have answered");
    Ok(Box::pin(Scrambled { inner: io }))
}

/// The listener's half: wait to be spoken to, which is the ordering TLS has.
///
/// It matters that the listener sends nothing until the initiator has begun. Were it to write
/// its new greeting first, those octets would reach a peer that has not swapped yet and would
/// be read as BEEP, ending the session — the same ordering trap the real profile has.
async fn server_swap(mut io: BoxedTransport) -> vortice::Result<BoxedTransport> {
    let mut hello = [0u8; 1];
    io.read_exact(&mut hello).await?;
    assert_eq!(hello, [0x01], "the initiator should have spoken first");
    io.write_all(b"\x02").await?;
    io.flush().await?;
    Ok(Box::pin(Scrambled { inner: io }))
}

/// The configuration a session takes on once the transport has been replaced.
fn upgraded_config(role: Role) -> Config {
    Config::new(role).with_profile(ECHO).with_profile(AFTER)
}

/// Starts a listener that swaps its transport when asked on the upgrade profile.
async fn start() -> String {
    let router = Router::new()
        .profile(ECHO, |responder: Responder, message: Message| async move {
            let _ = responder.reply(message.msgno, message.payload).await;
        })
        .profile(
            UPGRADE,
            |responder: Responder, message: Message| async move {
                // The reply and the swap go together: see `Responder::upgrade`.
                let _ = responder
                    .reply_then_upgrade(
                        message.msgno,
                        "<proceed />",
                        upgraded_config(Role::Listener),
                        server_swap,
                    )
                    .await;
            },
        );

    let server = Server::bind_with(
        "127.0.0.1:0",
        Config::new(Role::Listener).with_profile(UPGRADE),
        router,
    )
    .await
    .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());
    address
}

/// Drives a client up to and through the swap, returning the live session.
async fn upgraded_client(address: &str) -> Connection {
    let mut session = within(Connection::connect(
        address,
        Config::new(Role::Initiator).with_profile(UPGRADE),
    ))
    .await
    .expect("connect");

    let channel = within(session.open_channel(Profile::new(UPGRADE)))
        .await
        .expect("open the upgrade channel");
    let reply = within(channel.request("<ready />"))
        .await
        .expect("the listener should agree");
    assert_eq!(reply.payload(), b"<proceed />");

    let greeting = within(session.upgrade(upgraded_config(Role::Initiator), client_swap))
        .await
        .expect("the transport should be replaced");
    assert!(
        greeting.advertises(AFTER),
        "the greeting after the swap should be a new one, not the one from before"
    );

    session
}

#[tokio::test]
async fn a_session_continues_over_a_replaced_transport() {
    let address = start().await;
    let session = upgraded_client(&address).await;

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel on the new session");
    let reply = within(channel.request("after the swap"))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), b"after the swap");

    within(session.close()).await.expect("close");
}

/// Fragmentation, windows and `SEQ` pacing all have to work over the replacement too.
#[tokio::test]
async fn a_large_payload_survives_the_swap() {
    let address = start().await;
    let session = upgraded_client(&address).await;

    let channel = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel");
    let payload: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
    let reply = within(channel.request(payload.clone()))
        .await
        .expect("reply");
    assert_eq!(reply.payload(), &payload[..]);
}

/// RFC3080 §3.1: the old session is gone, not suspended.
#[tokio::test]
async fn channels_from_before_the_swap_stop_working() {
    let address = start().await;
    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator).with_profile(UPGRADE),
    ))
    .await
    .expect("connect");

    // A channel on the old session, opened before anything is swapped.
    let channel = within(session.open_channel(Profile::new(UPGRADE)))
        .await
        .expect("open the upgrade channel");
    let reply = within(channel.request("<ready />"))
        .await
        .expect("the listener should agree");
    assert_eq!(reply.payload(), b"<proceed />");

    within(session.upgrade(upgraded_config(Role::Initiator), client_swap))
        .await
        .expect("the transport should be replaced");

    let error = within(channel.request("is anyone there"))
        .await
        .expect_err("a channel from the old session must not still work");
    assert!(
        matches!(error, Error::Closed | Error::Protocol(_)),
        "expected the old channel to report the session gone, got {error}"
    );
}

/// A handshake that fails takes the session with it: the old transport is already gone.
#[tokio::test]
async fn a_failed_swap_ends_the_session() {
    let address = start().await;
    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator).with_profile(UPGRADE),
    ))
    .await
    .expect("connect");

    let channel = within(session.open_channel(Profile::new(UPGRADE)))
        .await
        .expect("open the upgrade channel");
    within(channel.request("<ready />"))
        .await
        .expect("the listener should agree");

    let error = within(
        session.upgrade(upgraded_config(Role::Initiator), |_io| async {
            Err(Error::Closed)
        }),
    )
    .await
    .expect_err("the swap refused");
    assert!(matches!(error, Error::Closed), "got {error}");

    within(session.closed()).await;
}

/// The shape BEEP's TLS profile actually uses: the agreement is piggybacked on the channel
/// exchange, so there is no reply left to send by the time a handler runs — only a transport
/// to replace, and a window in which nothing may be read.
struct PiggybackUpgrade;

impl Handler for PiggybackUpgrade {
    fn handle(&self, _responder: Responder, _message: Message) -> HandlerFuture {
        Box::pin(core::future::ready(()))
    }

    fn accept(&self, uri: &str, _start: &Start) -> Result<Profile, vortice::ErrorReply> {
        Ok(Profile::new(uri).with_content("<proceed />"))
    }

    fn upgrades_transport(&self) -> bool {
        true
    }

    fn on_open(&self, responder: Responder) -> HandlerFuture {
        Box::pin(async move {
            let _ = responder
                .upgrade(upgraded_config(Role::Listener), server_swap)
                .await;
        })
    }
}

#[tokio::test]
async fn the_transport_is_replaced_from_the_channel_exchange_itself() {
    let router = Router::new()
        .profile(ECHO, |responder: Responder, message: Message| async move {
            let _ = responder.reply(message.msgno, message.payload).await;
        })
        .profile(UPGRADE, PiggybackUpgrade);

    let server = Server::bind_with(
        "127.0.0.1:0",
        Config::new(Role::Listener).with_profile(UPGRADE),
        router,
    )
    .await
    .expect("bind");
    let address = server.local_addr().expect("local address").to_string();
    tokio::spawn(server.serve());

    let mut session = within(Connection::connect(
        address.as_str(),
        Config::new(Role::Initiator).with_profile(UPGRADE),
    ))
    .await
    .expect("connect");

    // `<ready />` rides along on the start, and the answer carries `<proceed />` back.
    let channel = within(session.open_channel(Profile::new(UPGRADE).with_content("<ready />")))
        .await
        .expect("the listener should agree to the upgrade");
    assert_eq!(
        channel.profile().content.as_deref(),
        Some("<proceed />"),
        "the agreement should have come back piggybacked"
    );

    let greeting = within(session.upgrade(upgraded_config(Role::Initiator), client_swap))
        .await
        .expect("the transport should be replaced");
    assert!(greeting.advertises(AFTER));

    let echo = within(session.open_channel(Profile::new(ECHO)))
        .await
        .expect("open a channel on the new session");
    let reply = within(echo.request("piggybacked")).await.expect("reply");
    assert_eq!(reply.payload(), b"piggybacked");
}
