// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Presenting a WebSocket as the byte stream a BEEP session expects.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vortice_proto::codec::frame_boundary;

use crate::codec::{Decoder, Event};
use crate::frame::{self, MAX_SEND_BATCH, OpCode};

/// How much encoded output may pile up before a write waits for the socket to drain.
///
/// Without a ceiling a peer that stops reading would let the send buffer grow until the
/// process died. BEEP has its own window-based flow control, but it governs one channel's
/// payload, not the octets a slow socket has yet to accept.
const OUTBOUND_HIGH_WATER: usize = 512 * 1024;

/// How much is read from the socket in one go.
const READ_CHUNK: usize = 8 * 1024;

/// Which end of the connection this is, which decides whether frames are masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The end that opened the connection. RFC6455 §5.3 requires it to mask.
    Client,
    /// The end that accepted it. §5.1 requires it not to.
    Server,
}

/// A WebSocket carrying a BEEP session, seen as an ordinary byte stream.
///
/// This is the whole of the WebSocket binding. Because it implements `AsyncRead` and
/// `AsyncWrite`, [`vortice::Connection::from_io`] and [`vortice::Connection::serve_io`] run
/// over it with no change at all — the BEEP layer never learns it is not on a socket.
///
/// Reads deliver frame payloads with the message boundaries removed, writes put each write
/// into a binary frame, and pings are answered without the layer above seeing them.
#[derive(Debug)]
pub struct WsStream<T> {
    io: T,
    side: Side,
    /// Raw octets read from the transport, not yet decoded.
    inbound: BytesMut,
    /// Decoded payload waiting to be handed up.
    payload: BytesMut,
    /// Encoded frames waiting to go out.
    outbound: BytesMut,
    /// The tail of a write that was not a whole BEEP frame, held until the rest arrives.
    ///
    /// A WebSocket frame must carry exactly one BEEP frame, so an incomplete one cannot be
    /// put on the wire: it waits here for the write that finishes it. The session driver
    /// hands over whole frames and never fills this, but `AsyncWrite` promises nothing of the
    /// sort, and a flush empties it rather than let anything be held indefinitely.
    partial: BytesMut,
    decoder: Decoder,
    /// Set once the peer's close frame or end of file has been seen.
    finished: bool,
    /// Set once our own close frame has been queued, so it is queued only once.
    closing: bool,
}

impl<T> WsStream<T> {
    /// Wraps a transport whose handshake has already been done.
    fn new(io: T, side: Side, prefix: Bytes) -> Self {
        Self {
            io,
            side,
            inbound: BytesMut::from(&prefix[..]),
            payload: BytesMut::new(),
            outbound: BytesMut::new(),
            partial: BytesMut::new(),
            decoder: Decoder::new(),
            finished: false,
            closing: false,
        }
    }

    /// The client end of a WebSocket, which masks what it sends.
    ///
    /// `prefix` is whatever was read past the handshake response and so already belongs to
    /// the peer's first frame.
    pub fn client(io: T, prefix: Bytes) -> Self {
        Self::new(io, Side::Client, prefix)
    }

    /// The server end of a WebSocket, which does not mask what it sends.
    ///
    /// `prefix` is whatever was read past the handshake request.
    pub fn server(io: T, prefix: Bytes) -> Self {
        Self::new(io, Side::Server, prefix)
    }

    /// Puts one frame into the outgoing buffer.
    fn queue(&mut self, opcode: OpCode, payload: &[u8]) -> io::Result<()> {
        let mask = match self.side {
            Side::Client => Some(frame::masking_key().map_err(|_| {
                io::Error::other("the operating system had no randomness for a masking key")
            })?),
            Side::Server => None,
        };

        frame::encode_header(&mut self.outbound, opcode, true, payload.len(), mask);
        let at = self.outbound.len();
        self.outbound.extend_from_slice(payload);
        if let Some(mask) = mask {
            frame::apply_mask(&mut self.outbound[at..], mask, 0);
        }
        Ok(())
    }

    /// Queues every whole BEEP frame held back so far, one WebSocket frame each.
    ///
    /// Returns how much payload that was, which is what the batching budget counts.
    fn queue_whole_frames(&mut self) -> io::Result<usize> {
        let mut queued = 0;
        while let Some(end) = frame_boundary(&self.partial) {
            let frame = self.partial.split_to(end);
            self.queue(OpCode::Binary, &frame)?;
            queued += end;
        }
        Ok(queued)
    }

    /// Puts whatever is still held back on the wire, whole frame or not.
    ///
    /// A flush is the caller saying there is nothing more coming, so holding octets back any
    /// longer would lose them. The BEEP driver flushes only between frames, so in this
    /// crate's own use there is never anything here; a caller that flushes mid-frame gets a
    /// split frame, which is better than silence.
    fn flush_partial(&mut self) -> io::Result<()> {
        self.queue_whole_frames()?;
        if !self.partial.is_empty() {
            let rest = std::mem::take(&mut self.partial);
            self.queue(OpCode::Binary, &rest)?;
        }
        Ok(())
    }
}

impl<T: AsyncWrite + Unpin> WsStream<T> {
    /// Pushes as much of the outgoing buffer into the transport as it will take.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outbound.is_empty() {
            match ready!(Pin::new(&mut self.io).poll_write(cx, &self.outbound)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(written) => self.outbound.advance(written),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            if !this.payload.is_empty() {
                let take = this.payload.len().min(buf.remaining());
                let chunk = this.payload.split_to(take);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            // Leaving `buf` untouched is how `AsyncRead` spells end of file.
            if this.finished {
                return Poll::Ready(Ok(()));
            }

            match this
                .decoder
                .poll(&mut this.inbound)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            {
                Some(Event::Data(data)) => {
                    this.payload.extend_from_slice(&data);
                    continue;
                }
                Some(Event::Ping(data)) => {
                    // Answered here rather than by the session: the layer above is speaking
                    // BEEP and knows nothing about WebSocket liveness.
                    this.queue(OpCode::Pong, &data)?;
                    // Best effort in both senses: if the socket is full the pong waits with
                    // everything else, and if the write side is already broken that is for the
                    // next read or write to report, not for a courtesy frame to raise.
                    let _ = this.poll_drain(cx);
                    continue;
                }
                Some(Event::Pong(_)) => continue,
                Some(Event::Close { code, reason }) => {
                    tracing::debug!(
                        ?code,
                        reason = %String::from_utf8_lossy(&reason),
                        "peer closed the websocket"
                    );
                    this.finished = true;
                    if !this.closing {
                        this.closing = true;
                        // §5.5.1 asks for a close in answer to a close. A peer that closed
                        // the socket in the same breath makes that write fail, which must not
                        // turn an orderly close into a read error: we already have its close,
                        // so the stream is finished either way.
                        this.queue(OpCode::Close, &1000u16.to_be_bytes())?;
                        let _ = this.poll_drain(cx);
                    }
                    continue;
                }
                None => {}
            }

            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                // The transport ended without a close frame. Not tidy, but nothing is lost
                // that a close would have carried, so treat it as end of file.
                this.finished = true;
                continue;
            }
            this.inbound.extend_from_slice(read.filled());
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Wait for room rather than buffering without bound. `poll_drain` has registered the
        // waker by the time it yields `Pending`.
        while this.outbound.len() >= OUTBOUND_HIGH_WATER {
            ready!(this.poll_drain(cx))?;
        }

        // One BEEP frame per WebSocket frame, but as many of them per write as are ready.
        //
        // The rule LibVortex needs is about the wire — a WebSocket frame it reads must hold
        // exactly one BEEP frame — and says nothing about how many go out per call. Emitting
        // only one and returning was the obvious reading of that, and it is catastrophic over
        // a transport that packages each write: every BEEP frame became its own TLS record,
        // and a bulk transfer that takes under two seconds took over two minutes.
        //
        // The rule is kept in both directions here. A BEEP frame larger than the batching
        // budget goes out whole rather than being cut in two, and a write that ends in the
        // middle of one holds the remainder back instead of sending half a frame.
        let mut taken = 0;
        let mut queued = 0;

        // What is already held back is the head of the stream, so it has to be completed
        // before anything in this write can be looked at on its own.
        if !this.partial.is_empty() {
            this.partial.extend_from_slice(buf);
            taken = buf.len();
            queued += this.queue_whole_frames()?;
        }

        while taken < buf.len() && queued < MAX_SEND_BATCH {
            let rest = &buf[taken..];
            match frame_boundary(rest) {
                Some(end) => {
                    this.queue(OpCode::Binary, &rest[..end])?;
                    taken += end;
                    queued += end;
                }
                None => {
                    this.partial.extend_from_slice(rest);
                    taken = buf.len();
                }
            }
        }

        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.flush_partial()?;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.flush_partial()?;
        if !this.closing {
            this.closing = true;
            this.queue(OpCode::Close, &1000u16.to_be_bytes())?;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::WsStream;
    use crate::codec::{Decoder, Event};
    use crate::frame::{self, MAX_SEND_BATCH, OpCode};
    use bytes::{Bytes, BytesMut};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Builds one frame the way a peer would.
    fn frame(opcode: OpCode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut buffer = BytesMut::new();
        frame::encode_header(&mut buffer, opcode, true, payload.len(), mask);
        let at = buffer.len();
        buffer.extend_from_slice(payload);
        if let Some(mask) = mask {
            frame::apply_mask(&mut buffer[at..], mask, 0);
        }
        buffer.to_vec()
    }

    /// Decodes everything a stream wrote, as its peer would.
    fn decode(wire: &[u8]) -> Vec<Event> {
        let mut buffer = BytesMut::from(wire);
        let mut decoder = Decoder::new();
        let mut events = Vec::new();
        while let Some(event) = decoder.poll(&mut buffer).expect("valid framing") {
            events.push(event);
        }
        events
    }

    /// A stream whose peer has already sent `wire`, over an in-memory duplex.
    async fn with_peer_sending(wire: Vec<u8>) -> WsStream<tokio::io::DuplexStream> {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        theirs.write_all(&wire).await.expect("peer write");
        // Dropping the peer ends the transport, so the stream sees end of file after `wire`.
        drop(theirs);
        WsStream::server(ours, Bytes::new())
    }

    #[tokio::test]
    async fn reads_payload_with_the_framing_removed() {
        let mut wire = frame(OpCode::Binary, b"RPY 0 0 . ", None);
        wire.extend_from_slice(&frame(OpCode::Binary, b"0 0\r\nEND\r\n", None));

        let mut stream = with_peer_sending(wire).await;
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.expect("read");
        assert_eq!(read, b"RPY 0 0 . 0 0\r\nEND\r\n");
    }

    #[tokio::test]
    async fn replays_a_prefix_read_during_the_handshake() {
        let (ours, theirs) = tokio::io::duplex(1024);
        drop(theirs);

        let prefix = Bytes::from(frame(OpCode::Binary, b"already here", None));
        let mut stream = WsStream::server(ours, prefix);

        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.expect("read");
        assert_eq!(read, b"already here");
    }

    /// The interop requirement, end to end: LibVortex sends BEEP inside text frames.
    #[tokio::test]
    async fn reads_a_text_frame_holding_octets_that_are_not_utf8() {
        let payload = [0x00u8, 0xff, 0xc0, 0x80, 0x41];
        let mut stream = with_peer_sending(frame(OpCode::Text, &payload, None)).await;

        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.expect("read");
        assert_eq!(read, payload);
    }

    /// A peer that closes the socket in the same breath as its close frame must still read
    /// as an orderly end of stream, not as a write error on the close we send back.
    #[tokio::test]
    async fn a_close_frame_ends_the_stream() {
        let mut wire = frame(OpCode::Binary, b"last words", None);
        wire.extend_from_slice(&frame(OpCode::Close, &1000u16.to_be_bytes(), None));
        wire.extend_from_slice(&frame(OpCode::Binary, b"never seen", None));

        let mut stream = with_peer_sending(wire).await;
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.expect("read");
        assert_eq!(
            read, b"last words",
            "nothing after the close frame should be delivered"
        );
    }

    #[tokio::test]
    async fn a_ping_is_answered_without_the_session_seeing_it() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        theirs
            .write_all(&frame(OpCode::Ping, b"probe", None))
            .await
            .expect("peer write");
        theirs
            .write_all(&frame(OpCode::Binary, b"payload", None))
            .await
            .expect("peer write");

        let mut stream = WsStream::server(ours, Bytes::new());
        let mut read = [0u8; 7];
        stream.read_exact(&mut read).await.expect("read");
        assert_eq!(&read, b"payload", "the ping must not reach the session");

        let mut answer = vec![0u8; 7];
        theirs.read_exact(&mut answer).await.expect("read the pong");
        assert_eq!(
            decode(&answer),
            vec![Event::Pong(Bytes::from_static(b"probe"))]
        );
    }

    #[tokio::test]
    async fn a_server_writes_unmasked_binary_frames() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        stream.write_all(b"MSG 0 0 . 0 0").await.expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(wire[0], 0x82, "FIN set, binary opcode");
        assert_eq!(wire[1] & 0x80, 0, "a server must not mask");
        assert_eq!(
            decode(&wire).first(),
            Some(&Event::Data(Bytes::from_static(b"MSG 0 0 . 0 0")))
        );
    }

    #[tokio::test]
    async fn a_client_masks_what_it_writes() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::client(ours, Bytes::new());

        stream.write_all(b"MSG 0 0 . 0 0").await.expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(wire[1] & 0x80, 0x80, "a client must mask");
        assert_eq!(
            decode(&wire).first(),
            Some(&Event::Data(Bytes::from_static(b"MSG 0 0 . 0 0"))),
            "and the payload must survive the masking"
        );
    }

    /// The interoperability rule: one BEEP frame per WebSocket frame. LibVortex reads only
    /// the first frame of a WebSocket frame that holds several, so coalescing kills the
    /// session — see the framing note in the crate documentation.
    #[tokio::test]
    async fn one_write_holding_two_beep_frames_becomes_two_websocket_frames() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        stream
            .write_all(b"RPY 0 0 . 0 5\r\nhelloEND\r\nRPY 0 1 . 5 2\r\nhiEND\r\n")
            .await
            .expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(
            decode(&wire),
            vec![
                Event::Data(Bytes::from_static(b"RPY 0 0 . 0 5\r\nhelloEND\r\n")),
                Event::Data(Bytes::from_static(b"RPY 0 1 . 5 2\r\nhiEND\r\n")),
            ]
        );
    }

    /// A SEQ frame is a header line with no payload, so its boundary is the line itself.
    #[tokio::test]
    async fn a_seq_frame_is_not_merged_with_what_follows_it() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        stream
            .write_all(b"SEQ 0 4096 4096\r\nRPY 0 0 . 0 2\r\nhiEND\r\n")
            .await
            .expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(
            decode(&wire),
            vec![
                Event::Data(Bytes::from_static(b"SEQ 0 4096 4096\r\n")),
                Event::Data(Bytes::from_static(b"RPY 0 0 . 0 2\r\nhiEND\r\n")),
            ]
        );
    }

    /// Builds one BEEP frame with a payload of `size` octets.
    fn beep_frame(msgno: u32, seqno: u32, size: usize) -> Vec<u8> {
        let mut frame = format!("MSG 0 {msgno} . {seqno} {size}\r\n").into_bytes();
        frame.extend((0..size).map(|index| (index % 251) as u8));
        frame.extend_from_slice(b"END\r\n");
        frame
    }

    /// The other half of the framing rule: a BEEP frame larger than the batching budget must
    /// not be cut in two. LibVortex reads one BEEP frame out of each WebSocket frame, so half
    /// a frame is a frame it cannot parse.
    #[tokio::test]
    async fn a_beep_frame_larger_than_the_batch_stays_in_one_websocket_frame() {
        let (ours, mut theirs) = tokio::io::duplex(4 * 1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        let frame = beep_frame(0, 0, MAX_SEND_BATCH * 3 + 17);
        stream.write_all(&frame).await.expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(decode(&wire), vec![Event::Data(Bytes::from(frame))]);
    }

    /// Several frames in one write are batched, but the batch stops at the budget so the
    /// socket gets a chance to drain — and every frame still travels whole and on its own.
    #[tokio::test]
    async fn a_batch_of_frames_stops_at_the_budget_without_splitting_one() {
        let (ours, mut theirs) = tokio::io::duplex(4 * 1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        let each = MAX_SEND_BATCH / 2;
        let frames: Vec<Vec<u8>> = (0..5).map(|n| beep_frame(n, n * 4, each)).collect();
        let batch: Vec<u8> = frames.concat();

        let written = stream.write(&batch).await.expect("write");
        assert!(
            written < batch.len(),
            "the budget should stop the batch short of the whole write"
        );
        stream.write_all(&batch[written..]).await.expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(
            decode(&wire),
            frames
                .into_iter()
                .map(|frame| Event::Data(Bytes::from(frame)))
                .collect::<Vec<_>>()
        );
    }

    /// A write ending mid-frame is held back rather than sent as half a BEEP frame.
    #[tokio::test]
    async fn a_write_ending_mid_frame_waits_for_the_rest() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());

        let frame = beep_frame(0, 0, 4096);
        let (head, tail) = frame.split_at(1000);
        stream.write_all(head).await.expect("write");

        // Nothing may be on the wire yet: what was handed over is not a whole BEEP frame.
        let mut wire = BytesMut::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), theirs.read_buf(&mut wire))
                .await
                .is_err(),
            "half a frame reached the peer: {wire:?}"
        );

        stream.write_all(tail).await.expect("write");
        stream.flush().await.expect("flush");
        drop(stream);

        let mut rest = Vec::new();
        theirs.read_to_end(&mut rest).await.expect("peer read");
        wire.extend_from_slice(&rest);
        assert_eq!(decode(&wire), vec![Event::Data(Bytes::from(frame))]);
    }

    #[tokio::test]
    async fn shutting_down_sends_a_close_frame() {
        let (ours, mut theirs) = tokio::io::duplex(1024 * 1024);
        let mut stream = WsStream::server(ours, Bytes::new());
        stream.shutdown().await.expect("shutdown");

        let mut wire = Vec::new();
        theirs.read_to_end(&mut wire).await.expect("peer read");
        assert_eq!(
            decode(&wire),
            vec![Event::Close {
                code: Some(1000),
                reason: Bytes::new(),
            }]
        );
    }

    #[tokio::test]
    async fn malformed_framing_becomes_a_read_error() {
        // A reserved bit set, which RFC6455 §5.2 forbids without an extension.
        let mut stream = with_peer_sending(vec![0x40, 0x00]).await;
        let mut read = Vec::new();
        let error = stream
            .read_to_end(&mut read)
            .await
            .expect_err("reserved bits should be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
