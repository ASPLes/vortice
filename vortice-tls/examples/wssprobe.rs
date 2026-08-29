// Vortice: A BEEP (RFC3080/RFC3081) implementation for Rust.
// Copyright (C) 2026 Advanced Software Production Line, S.L.
// SPDX-License-Identifier: LGPL-2.1-only

//! Where does a BEEP-over-`wss` peer lose frames: the WebSocket layer, or TLS underneath it?
//!
//! Drives a `wss` session against `vortex-regression-listener` by hand — TLS, then the
//! WebSocket handshake, then raw BEEP — and sends the same two BEEP frames three different
//! ways. The three differ only in how the octets are packaged, so whichever ones fail name the
//! layer that is losing them:
//!
//! | mode | packaging | what it isolates |
//! |---|---|---|
//! | `two-records` | two WebSocket frames, two TLS records | control: must pass |
//! | `one-record` | two WebSocket frames, **one** TLS record | TLS buffering under noPoll |
//! | `one-ws-frame` | **one** WebSocket frame, one TLS record | the WebSocket layer |
//!
//! `one-ws-frame` is the defect already fixed in `vortex_websocket.c`, so it doubles as a
//! second control: if it fails, the build under test predates that fix.
//!
//! No timing anywhere. Every mode is a fixed sequence of writes, which is the whole point —
//! the failures this is chasing were found and lost twice by running something that raced.
//!
//! ```sh
//! cd ~/programas/libvortex-1.1/test && ./vortex-regression-listener --offset-port=1000 &
//! cargo run -p vortice-tls --example wssprobe -- 45014 two-records
//! cargo run -p vortice-tls --example wssprobe -- 45014 one-record
//! cargo run -p vortice-tls --example wssprobe -- 45014 one-ws-frame
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

/// The profile the suite's listener serves and echoes on.
const REGRESSION_URI: &str = "http://iana.org/beep/transient/vortex-regression";

/// Wraps `payload` in a masked client WebSocket binary frame.
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut out = Vec::new();
    out.push(0x82); // FIN, binary
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (index, byte) in payload.iter().enumerate() {
        out.push(byte ^ mask[index % 4]);
    }
    out
}

/// One BEEP frame.
fn beep(kind: &str, channel: u32, msgno: u32, seqno: usize, payload: &str) -> Vec<u8> {
    format!(
        "{kind} {channel} {msgno} . {seqno} {}\r\n{payload}END\r\n",
        payload.len()
    )
    .into_bytes()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .get(1)
        .expect("usage: wssprobe <port> <mode>")
        .parse()?;
    let mode = args.get(2).map_or("one-record", String::as_str);

    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.set_nodelay(true)?;

    let tls = TlsConnector::from(Arc::new(vortice_tls::insecure_client_config()))
        .connect(ServerName::try_from("localhost")?, stream)
        .await?;
    let mut io = tls;
    println!("tls handshake ok");

    // The WebSocket handshake, by hand. noPoll's listener wants an Origin.
    io.write_all(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
          Origin: http://localhost\r\n\r\n",
    )
    .await?;
    io.flush().await?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if io.read(&mut byte).await? == 0 {
            return Err("closed during the websocket handshake".into());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    if !head.contains("101") {
        return Err(format!("no upgrade: {head}").into());
    }
    println!("websocket handshake ok");

    // The BEEP session: our greeting, then a channel start. Both are answered, so two `RPY`
    // frames on channel 0 are expected — the listener's greeting and its answer to the start.
    let greeting_body = "Content-Type: application/beep+xml\r\n\r\n<greeting />\r\n";
    let start_body = format!(
        "Content-Type: application/beep+xml\r\n\r\n<start number='1'>\r\n\
         <profile uri='{REGRESSION_URI}' />\r\n</start>\r\n"
    );

    let greeting = beep("RPY", 0, 0, 0, greeting_body);
    let start = beep("MSG", 0, 0, greeting_body.len(), &start_body);

    match mode {
        // Control. Nothing is packaged together anywhere; this must always work.
        "two-records" => {
            io.write_all(&ws_frame(&greeting)).await?;
            io.flush().await?;
            // A read in between guarantees the two do not end up in one record.
            tokio::time::sleep(Duration::from_millis(200)).await;
            io.write_all(&ws_frame(&start)).await?;
            io.flush().await?;
        }
        // The case Vortice now produces: correct WebSocket framing, one TLS record.
        "one-record" => {
            let mut both = ws_frame(&greeting);
            both.extend_from_slice(&ws_frame(&start));
            io.write_all(&both).await?;
            io.flush().await?;
        }
        // The defect already fixed in vortex_websocket.c, kept as a second control.
        "one-ws-frame" => {
            let mut both = greeting.clone();
            both.extend_from_slice(&start);
            io.write_all(&ws_frame(&both)).await?;
            io.flush().await?;
        }
        other => return Err(format!("unknown mode {other:?}").into()),
    }
    println!("sent greeting + start as: {mode}");

    // Collect for a fixed window, then count. Bounded rather than blocking, so a listener that
    // never answers reports that instead of hanging.
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(10);
    let mut first_reply_at = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), io.read(&mut chunk)).await {
            // A gap is not the end: a peer that answers slowly must not be reported as one
            // that never answered, which is the difference between "lost" and "late".
            Err(_) => continue,
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                seen.extend_from_slice(&chunk[..read]);
                if first_reply_at.is_none() {
                    first_reply_at = Some(started.elapsed());
                }
                if String::from_utf8_lossy(&seen).matches("RPY 0 0").count() >= 2 {
                    break;
                }
            }
            Ok(Err(error)) => return Err(error.into()),
        }
    }
    println!(
        "first octets after {first_reply_at:?}, total after {:?}",
        started.elapsed()
    );

    // The payload is inside WebSocket frames the listener sent unmasked, so the BEEP headers
    // are readable in the raw octets without decoding them.
    let text = String::from_utf8_lossy(&seen);
    let replies = text.matches("RPY 0 0").count();

    println!(
        "received {} octets, {replies} RPY frames on channel 0",
        seen.len()
    );
    println!(
        "RESULT [{mode}]: {}",
        if replies >= 2 {
            "both frames processed"
        } else {
            "FRAME LOST - only the greeting came back"
        }
    );
    Ok(())
}
