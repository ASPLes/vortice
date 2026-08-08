// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Putting already-read octets back in front of a stream.
//!
//! Any transport that has to look at the first octets before deciding what a connection is
//! needs this: reading the HTTP response head, reading a WebSocket handshake, or sniffing
//! whether a shared port carries BEEP directly or a handshake for it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream with a prefix of octets that were read too early.
///
/// Reading an HTTP response means reading until the blank line, and a peer that sends its
/// BEEP greeting immediately after the `101` will have had those octets swept up by the same
/// read. Handing the bare socket to a session would silently lose them, so the leftovers are
/// put back in front of it.
#[derive(Debug)]
pub struct Rewind<T> {
    prefix: Bytes,
    inner: T,
}

impl<T> Rewind<T> {
    /// Wraps `inner`, replaying `prefix` before anything the stream itself yields.
    pub const fn new(prefix: Bytes, inner: T) -> Self {
        Self { prefix, inner }
    }

    /// Whether anything is still waiting to be replayed.
    pub fn has_prefix(&self) -> bool {
        !self.prefix.is_empty()
    }

    /// The stream underneath, discarding anything not yet replayed.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Rewind<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let take = self.prefix.len().min(buf.remaining());
            let chunk = self.prefix.split_to(take);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Rewind<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn replays_the_prefix_before_the_stream() {
        let mut stream = Rewind::new(Bytes::from_static(b"early"), &b"late"[..]);
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(read, b"earlylate");
    }

    #[tokio::test]
    async fn an_empty_prefix_is_invisible() {
        let mut stream = Rewind::new(Bytes::new(), &b"only this"[..]);
        assert!(!stream.has_prefix());
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        assert_eq!(read, b"only this");
    }

    #[tokio::test]
    async fn replays_a_prefix_larger_than_one_read() {
        let mut stream = Rewind::new(Bytes::from_static(b"abcdef"), &b"gh"[..]);
        let mut small = [0u8; 2];
        let mut seen = Vec::new();
        loop {
            let n = stream.read(&mut small).await.unwrap();
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&small[..n]);
        }
        assert_eq!(seen, b"abcdefgh");
    }
}
