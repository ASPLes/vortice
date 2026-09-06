// Minimal, dependency-free probe: does LibVortex read two BEEP frames that arrive inside a
// single WebSocket frame?
//
// Speaks the WebSocket handshake by hand to vortex-regression-listener, then sends its BEEP
// greeting and a channel <start> either packed into one WebSocket frame or as two, and reports
// whether the listener answers the start.
//
//   rustc -O wsprobe.rs -o wsprobe && ./wsprobe <port> packed|split

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Wraps `payload` in a masked client WebSocket binary frame.
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut out = Vec::new();
    out.push(0x82); // FIN + binary
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

/// A BEEP frame with the given kind, channel, message number and sequence number.
fn beep(kind: &str, channel: u32, msgno: u32, seqno: usize, payload: &str) -> Vec<u8> {
    format!(
        "{kind} {channel} {msgno} . {seqno} {}\r\n{payload}END\r\n",
        payload.len()
    )
    .into_bytes()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let port: u16 = args[1].parse().expect("port");
    let packed = args[2] == "packed";

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
              Origin: http://localhost\r\n\r\n",
        )
        .expect("write handshake");

    // Read until the end of the response head; anything past it is already websocket.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).expect("read handshake") == 0 {
            panic!("closed during handshake");
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.contains("101"), "no upgrade: {head}");
    println!("handshake ok");

    let greeting_body = "Content-Type: application/beep+xml\r\n\r\n<greeting />\r\n";
    let greeting = beep("RPY", 0, 0, 0, greeting_body);

    let start_body = "Content-Type: application/beep+xml\r\n\r\n<start number='1'>\r\n\
                      <profile uri='http://iana.org/beep/transient/vortex-regression' />\r\n\
                      </start>\r\n";
    let start = beep("MSG", 0, 0, greeting_body.len(), start_body);

    if packed {
        // Both BEEP frames inside ONE websocket frame.
        let mut both = greeting.clone();
        both.extend_from_slice(&start);
        stream.write_all(&ws_frame(&both)).expect("write packed");
        println!("sent greeting + start packed into 1 websocket frame");
    } else {
        stream.write_all(&ws_frame(&greeting)).expect("write");
        stream.write_all(&ws_frame(&start)).expect("write");
        println!("sent greeting + start as 2 websocket frames");
    }

    // Read until the peer goes quiet for the timeout, then count BEEP frames. The listener's
    // greeting is itself an `RPY 0 0`, so the reply to our start is the *second* one — looking
    // for `<profile` would match the greeting, which advertises profiles too.
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
        }
    }

    let text = String::from_utf8_lossy(&seen);
    let replies = text.matches("RPY 0 0").count();
    println!("received {} octets, {replies} RPY frames on channel 0", seen.len());
    println!(
        "RESULT: start answered: {}",
        if replies >= 2 {
            "yes"
        } else {
            "NO - only the greeting came back, the second BEEP frame was never processed"
        }
    );
}
