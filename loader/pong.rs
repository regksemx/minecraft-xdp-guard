//! Keeps the `pong_cache` map fresh: the filter answers Bedrock server list
//! pings itself, with whatever the real server answered last.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use aya::maps::{Array, MapData};
use aya::{Ebpf, Pod};
use log::{info, warn};

use crate::config::Config;
use crate::ebpf::monotonic_ns;
use crate::shutdown::Shutdown;

const MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];
const UNCONNECTED_PING: u8 = 0x01;
const UNCONNECTED_PONG: u8 = 0x1c;

/// `PONG_MAX` in xdp/common.h.
const PONG_MAX: usize = 512;
/// Id and echoed ping time, the part of a pong the filter writes itself.
const PONG_HEADER_LEN: usize = 9;

/// Userspace mirror of `struct pong_cache` in xdp/common.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct PongCache {
    updated: u64,
    len: u32,
    pad: u32,
    data: [u8; PONG_MAX],
}

// SAFETY: repr(C) struct of integers and bytes without padding, valid for
// any bit pattern.
unsafe impl Pod for PongCache {}

/// How long the filter may use a pong: a few missed refreshes are fine,
/// after that the pings go to the server again.
pub fn max_age_secs(config: &Config) -> u64 {
    config.bedrock.pong_refresh_secs * 3 + 2
}

fn ping() -> Vec<u8> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let mut packet = vec![UNCONNECTED_PING];
    packet.extend_from_slice(&millis.to_be_bytes());
    packet.extend_from_slice(&MAGIC);
    packet.extend_from_slice(&u64::from(std::process::id()).to_be_bytes()); // client guid
    packet
}

/// The part of an unconnected pong the filter replays: everything after the
/// echoed ping time (server guid, magic, MOTD). `None` if `packet` is not a
/// well-formed pong or does not fit the cache.
fn pong_body(packet: &[u8]) -> Option<&[u8]> {
    let body = packet.get(PONG_HEADER_LEN..)?;
    let well_formed = packet[0] == UNCONNECTED_PONG
        && body.len() >= 8 + MAGIC.len() + 2
        && body.len() <= PONG_MAX
        && body[8..8 + MAGIC.len()] == MAGIC
        // the MOTD is the rest of the packet
        && usize::from(u16::from_be_bytes([body[24], body[25]])) == body.len() - 26;
    well_formed.then_some(body)
}

fn fetch(socket: &UdpSocket) -> Result<Vec<u8>> {
    socket.send(&ping()).context("failed to send the ping")?;
    let mut buffer = [0u8; 2048];
    let len = socket.recv(&mut buffer).context("no answer")?;
    match pong_body(&buffer[..len]) {
        Some(body) => Ok(body.to_vec()),
        None => bail!("the answer is not a pong the filter can replay ({len} bytes)"),
    }
}

/// Starts the refresh thread if `[bedrock] pong_from` is set.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if config.bedrock.pong_from.is_empty() {
        return Ok(None);
    }
    let server: SocketAddr = config
        .bedrock
        .pong_from
        .parse()
        .context("[bedrock] pong_from")?;
    let map = ebpf
        .take_map("pong_cache")
        .context("can't take map 'pong_cache'")?;
    let mut cache: Array<MapData, PongCache> = Array::try_from(map)?;

    let socket = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .context("failed to open a socket for the pong refresh")?;
    socket.connect(server)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    let interval = Duration::from_secs(config.bedrock.pong_refresh_secs);
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("pong-refresh".into())
        .spawn(move || {
            // None until the first attempt, so that both outcomes are logged once
            let mut answering: Option<bool> = None;
            loop {
                let refreshed = fetch(&socket).and_then(|body| {
                    let mut entry = PongCache {
                        updated: monotonic_ns()?,
                        len: body.len() as u32,
                        pad: 0,
                        data: [0; PONG_MAX],
                    };
                    entry.data[..body.len()].copy_from_slice(&body);
                    cache.set(0, entry, 0).context("failed to update map 'pong_cache'")
                });
                match refreshed {
                    Ok(()) if answering != Some(true) => {
                        info!("Answering Bedrock pings with the pong of {server}");
                        answering = Some(true);
                    }
                    Ok(()) => {}
                    Err(e) if answering != Some(false) => {
                        warn!("No pong from {server} ({e:#}); pings go to the server until it answers again");
                        answering = Some(false);
                    }
                    Err(_) => {}
                }
                if !shutdown.sleep(interval) {
                    return;
                }
            }
        })?;
    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pong(motd: &[u8]) -> Vec<u8> {
        let mut packet = vec![UNCONNECTED_PONG];
        packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // echoed time
        packet.extend_from_slice(&[9; 8]); // server guid
        packet.extend_from_slice(&MAGIC);
        packet.extend_from_slice(&(motd.len() as u16).to_be_bytes());
        packet.extend_from_slice(motd);
        packet
    }

    #[test]
    fn ping_is_what_the_filter_accepts() {
        // id, time, magic, guid: RAKNET_PING_LEN in xdp/bedrock.h
        let packet = ping();
        assert_eq!(packet.len(), 33);
        assert_eq!(packet[0], UNCONNECTED_PING);
        assert_eq!(packet[9..25], MAGIC);
    }

    #[test]
    fn extracts_the_replayable_part() {
        let packet = pong(b"MCPE;server;800;1.21.50;1;10;");
        let body = pong_body(&packet).unwrap();
        assert_eq!(body, &packet[9..]);
        assert_eq!(body.len(), 8 + 16 + 2 + 29);
        assert!(pong_body(&pong(b"")).is_some());
        // exactly as much as the cache holds
        assert!(pong_body(&pong(&[b'x'; PONG_MAX - 26])).is_some());
        assert!(pong_body(&pong(&[b'x'; PONG_MAX - 25])).is_none());
    }

    #[test]
    fn rejects_everything_else() {
        let good = pong(b"MCPE;");
        assert!(pong_body(&[]).is_none());
        assert!(pong_body(&good[..20]).is_none());
        let mut wrong_id = good.clone();
        wrong_id[0] = 0x1d;
        assert!(pong_body(&wrong_id).is_none());
        let mut wrong_magic = good.clone();
        wrong_magic[20] ^= 1;
        assert!(pong_body(&wrong_magic).is_none());
        // MOTD length that does not match the packet
        let mut truncated = good.clone();
        truncated.pop();
        assert!(pong_body(&truncated).is_none());
        let mut padded = good;
        padded.push(0);
        assert!(pong_body(&padded).is_none());
    }
}
