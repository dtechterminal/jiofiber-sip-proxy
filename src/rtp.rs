use std::{
    net::{IpAddr, SocketAddr},
    ptr::NonNull,
};

use anyhow::{Context, Result};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};
use uuid::Uuid;

use crate::sdp::{Codec, Description, Side};

#[allow(non_upper_case_globals, dead_code)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/amr.rs"));
}

pub const FRAME: usize = 160;
const AMR_BYTES: [usize; 9] = [12, 13, 15, 17, 19, 20, 26, 31, 5];

struct Amr {
    encoder: NonNull<std::ffi::c_void>,
    decoder: NonNull<std::ffi::c_void>,
}

// These states own independent OpenCORE allocations accessed only through &mut self.
unsafe impl Send for Amr {}

impl Amr {
    fn new() -> Result<Self> {
        // The library returns owned state pointers or null on allocation failure.
        let encoder = NonNull::new(unsafe { ffi::Encoder_Interface_init(0) })
            .context("creating AMR encoder")?;
        let Some(decoder) = NonNull::new(unsafe { ffi::Decoder_Interface_init() }) else {
            unsafe { ffi::Encoder_Interface_exit(encoder.as_ptr()) };
            anyhow::bail!("creating AMR decoder");
        };
        Ok(Self { encoder, decoder })
    }

    fn encode(&mut self, pcm: &[i16; FRAME], mode: u8) -> Vec<u8> {
        let mut bytes = [0; 33];
        bytes[0] = 0xf0; // CMR=15 means no mode request.
        // OpenCORE writes an octet-aligned ToC and at most 31 bytes of speech.
        let n = unsafe {
            ffi::Encoder_Interface_Encode(
                self.encoder.as_ptr(),
                mode.into(),
                pcm.as_ptr(),
                bytes[1..].as_mut_ptr(),
                0,
            )
        };
        bytes[..1 + n as usize].to_vec()
    }

    fn decode(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let (_, entries) = payload.split_first()?;
        let last = entries.iter().take(32).position(|toc| toc & 0x80 == 0)?;
        let (tocs, frames) = entries.split_at(last + 1);
        let lengths = tocs
            .iter()
            .map(|toc| match (toc >> 3) & 0x0f {
                ft @ 0..=8 => Some(AMR_BYTES[ft as usize]),
                15 => Some(0),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if lengths.iter().sum::<usize>() != frames.len() {
            return None;
        }
        let mut pcmu = Vec::with_capacity(tocs.len() * FRAME);
        let mut offset = 0;
        for (&toc, len) in tocs.iter().zip(lengths) {
            let mut frame = [0; 32];
            frame[0] = toc & 0x7c;
            frame[1..=len].copy_from_slice(&frames[offset..offset + len]);
            offset += len;
            let mut pcm = [0; FRAME];
            // Frame length was validated and output holds a full 20ms of samples.
            unsafe {
                ffi::Decoder_Interface_Decode(
                    self.decoder.as_ptr(),
                    frame.as_ptr(),
                    pcm.as_mut_ptr(),
                    i32::from(toc & 4 == 0 || len == 0),
                )
            };
            pcmu.extend(pcm.map(pcm_to_ulaw));
        }
        Some(pcmu)
    }
}

impl Drop for Amr {
    fn drop(&mut self) {
        unsafe {
            ffi::Encoder_Interface_exit(self.encoder.as_ptr());
            ffi::Decoder_Interface_exit(self.decoder.as_ptr());
        }
    }
}

pub fn pcm_to_ulaw(sample: i16) -> u8 {
    let sign = if sample < 0 { 0x80 } else { 0 };
    let magnitude = sample.unsigned_abs().min(32635) + 0x84;
    let exponent = (15 - magnitude.leading_zeros()).saturating_sub(7) as u8;
    !(sign | (exponent << 4) | ((magnitude >> (exponent + 3)) as u8 & 0x0f))
}

pub fn ulaw_to_pcm(byte: u8) -> i16 {
    let byte = !byte;
    let exponent = (byte >> 4) & 7;
    let mantissa = i16::from(byte & 15);
    let sample = ((mantissa << 3) + 0x84) << exponent;
    if byte & 0x80 == 0 {
        sample - 0x84
    } else {
        0x84 - sample
    }
}

fn pcm_to_alaw(sample: i16) -> u8 {
    let magnitude = (if sample < 0 { !sample } else { sample }) as u16;
    let exponent = (15 - (magnitude | 1).leading_zeros()).saturating_sub(7) as u8;
    let mantissa = (magnitude >> (exponent.max(1) + 3)) as u8 & 0x0f;
    (if sample < 0 { 0x55 } else { 0xd5 }) ^ (exponent << 4) ^ mantissa
}

fn alaw_to_pcm(byte: u8) -> i16 {
    let byte = byte ^ 0x55;
    let exponent = (byte >> 4) & 7;
    let mantissa = i16::from(byte & 15) << 4;
    let sample = if exponent == 0 {
        mantissa + 8
    } else {
        (mantissa + 0x108) << (exponent - 1)
    };
    if byte & 0x80 == 0 { -sample } else { sample }
}

pub struct Packet<'a> {
    pub pt: u8,
    pub marker: bool,
    pub ts: u32,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 || data[0] >> 6 != 2 {
            return None;
        }
        let mut offset = 12 + usize::from(data[0] & 0x0f) * 4;
        if data[0] & 0x10 != 0 {
            let extension = u16::from_be_bytes(data.get(offset + 2..offset + 4)?.try_into().ok()?);
            offset += 4 + 4 * usize::from(extension);
        }
        let mut end = data.len();
        if data[0] & 0x20 != 0 {
            let padding = usize::from(*data.last()?);
            if padding == 0 {
                return None;
            }
            end = end.checked_sub(padding)?;
        }
        Some(Self {
            pt: data[1] & 127,
            marker: data[1] & 128 != 0,
            ts: u32::from_be_bytes(data[4..8].try_into().ok()?),
            payload: data.get(offset..end)?,
        })
    }
}

pub struct Sequencer {
    sequence: u16,
    ssrc: u32,
}

impl Sequencer {
    pub fn new() -> Self {
        let bytes = Uuid::new_v4().into_bytes();
        Self {
            sequence: u16::from_be_bytes([bytes[0], bytes[1]]),
            ssrc: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        }
    }

    pub fn packet(&mut self, pt: u8, marker: bool, timestamp: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + payload.len());
        bytes.extend_from_slice(&[0x80, (pt & 127) | if marker { 0x80 } else { 0 }]);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.ssrc.to_be_bytes());
        bytes.extend_from_slice(payload);
        self.sequence = self.sequence.wrapping_add(1);
        bytes
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Peers {
    local: Option<Description>,
    upstream: Option<Description>,
}

pub struct Relay {
    pub local: SocketAddr,
    pub upstream: SocketAddr,
    peers: watch::Sender<Peers>,
    task: JoinHandle<()>,
}

impl Relay {
    pub async fn bind(local: IpAddr, upstream: IpAddr, port: u16) -> Result<Self> {
        let upstream_socket = UdpSocket::bind((upstream, port))
            .await
            .context("binding upstream RTP")?;
        let local_socket = UdpSocket::bind((local, 0))
            .await
            .context("binding local RTP")?;
        let (peers, rx) = watch::channel(Peers::default());
        let amr = Amr::new()?;
        Ok(Self {
            local: local_socket.local_addr()?,
            upstream: upstream_socket.local_addr()?,
            peers,
            task: tokio::spawn(relay(local_socket, upstream_socket, rx, amr)),
        })
    }

    pub fn set(&self, side: Side, description: Description) -> Result<()> {
        let addr = if side == Side::Upstream {
            self.upstream
        } else {
            self.local
        };
        anyhow::ensure!(
            description.remote.is_ipv6() == addr.is_ipv6(),
            "RTP address family differs from its SIP leg"
        );
        self.peers.send_if_modified(|peers| {
            let field = if side == Side::Upstream {
                &mut peers.upstream
            } else {
                &mut peers.local
            };
            let changed = *field != Some(description);
            *field = Some(description);
            changed
        });
        Ok(())
    }

    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }

    pub fn clear(&self, side: Side) {
        self.peers.send_modify(|peers| {
            if side == Side::Upstream {
                peers.upstream = None;
            } else {
                peers.local = None;
            }
        });
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct PcmBuffer {
    samples: Vec<i16>,
    timestamp: u32,
    marker: bool,
}

impl PcmBuffer {
    fn push(&mut self, packet: &Packet<'_>) {
        if self.samples.is_empty()
            || self.timestamp.wrapping_add(self.samples.len() as u32) != packet.ts
            || packet.marker
        {
            self.samples.clear();
            self.timestamp = packet.ts;
            self.marker = packet.marker;
        }
        self.samples
            .extend(packet.payload.iter().copied().map(ulaw_to_pcm));
    }
}

fn received(
    data: &[u8],
    peer: SocketAddr,
    source: Description,
    destination: Description,
) -> Option<Packet<'_>> {
    (source.remote == peer && source.can_send() && destination.can_receive())
        .then(|| Packet::parse(data))
        .flatten()
}

async fn relay(
    local: UdpSocket,
    upstream: UdpSocket,
    mut updates: watch::Receiver<Peers>,
    mut amr: Amr,
) {
    let mut local_bytes = [0; 4096];
    let mut upstream_bytes = [0; 4096];
    let mut to_local = Sequencer::new();
    let mut to_upstream = Sequencer::new();
    let mut pcm = PcmBuffer::default();
    let mut peers = Peers::default();
    loop {
        let (from, size, peer) = tokio::select! {
            result = updates.changed() => {
                if result.is_err() { break; }
                peers = *updates.borrow_and_update();
                pcm.samples.clear();
                continue;
            }
            result = local.recv_from(&mut local_bytes) => match result {
                Ok((size, peer)) => (Side::Local, size, peer),
                Err(_) => break,
            },
            result = upstream.recv_from(&mut upstream_bytes) => match result {
                Ok((size, peer)) => (Side::Upstream, size, peer),
                Err(_) => break,
            },
        };
        let (Some(local_peer), Some(upstream_peer)) = (peers.local, peers.upstream) else {
            continue;
        };
        if from == Side::Local {
            let Some(packet) = received(&local_bytes[..size], peer, local_peer, upstream_peer)
            else {
                continue;
            };
            if Some(packet.pt) == local_peer.events
                && let Some(pt) = upstream_peer.events
            {
                let _ = upstream
                    .send_to(
                        &to_upstream.packet(pt, packet.marker, packet.ts, packet.payload),
                        upstream_peer.remote,
                    )
                    .await;
            } else if local_peer.received_codec(packet.pt) == Some(Codec::Pcmu)
                && !packet.payload.is_empty()
            {
                let pt = upstream_peer.audio.pt;
                match upstream_peer.audio.codec {
                    Codec::Pcmu => {
                        let _ = upstream
                            .send_to(
                                &to_upstream.packet(pt, packet.marker, packet.ts, packet.payload),
                                upstream_peer.remote,
                            )
                            .await;
                    }
                    Codec::Pcma => {
                        let alaw: Vec<_> = packet
                            .payload
                            .iter()
                            .map(|&sample| pcm_to_alaw(ulaw_to_pcm(sample)))
                            .collect();
                        let _ = upstream
                            .send_to(
                                &to_upstream.packet(pt, packet.marker, packet.ts, &alaw),
                                upstream_peer.remote,
                            )
                            .await;
                    }
                    Codec::Amr { modes } => {
                        pcm.push(&packet);
                        let mode = (7 - modes.leading_zeros()) as u8;
                        for frame in pcm.samples.chunks_exact(FRAME) {
                            let samples = amr.encode(frame.try_into().unwrap(), mode);
                            let datagram =
                                to_upstream.packet(pt, pcm.marker, pcm.timestamp, &samples);
                            let _ = upstream.send_to(&datagram, upstream_peer.remote).await;
                            pcm.timestamp = pcm.timestamp.wrapping_add(FRAME as u32);
                            pcm.marker = false;
                        }
                        let consumed = pcm.samples.len() / FRAME * FRAME;
                        pcm.samples.drain(..consumed);
                    }
                }
            }
        } else {
            let Some(packet) = received(&upstream_bytes[..size], peer, upstream_peer, local_peer)
            else {
                continue;
            };
            let (pt, data) = if Some(packet.pt) == upstream_peer.events
                && let Some(pt) = local_peer.events
            {
                (pt, std::borrow::Cow::Borrowed(packet.payload))
            } else if let Some(codec) = upstream_peer.received_codec(packet.pt)
                && !packet.payload.is_empty()
            {
                let pcmu = match codec {
                    Codec::Pcmu => std::borrow::Cow::Borrowed(packet.payload),
                    Codec::Pcma => std::borrow::Cow::Owned(
                        packet
                            .payload
                            .iter()
                            .map(|&sample| pcm_to_ulaw(alaw_to_pcm(sample)))
                            .collect(),
                    ),
                    Codec::Amr { .. } => {
                        let Some(samples) = amr.decode(packet.payload) else {
                            continue;
                        };
                        std::borrow::Cow::Owned(samples)
                    }
                };
                (local_peer.audio.pt, pcmu)
            } else {
                continue;
            };
            let _ = local
                .send_to(
                    &to_local.packet(pt, packet.marker, packet.ts, &data),
                    local_peer.remote,
                )
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_handles_octet_aligned_frames_and_rejects_truncation() -> Result<()> {
        assert_eq!(pcm_to_ulaw(0), 0xff);
        assert_eq!(ulaw_to_pcm(0xff), 0);
        assert_eq!(ulaw_to_pcm(0x00), -32124);
        let mut amr = Amr::new()?;
        let source = std::array::from_fn(|sample| if sample % 40 < 20 { 4000 } else { -4000 });
        let encoded = amr.encode(&source, 7);
        assert_eq!(encoded.len(), 33);
        assert_eq!(&encoded[..2], &[0xf0, 0x3c]);
        assert_eq!(amr.decode(&encoded).unwrap().len(), FRAME);
        assert!(amr.decode(&encoded[..32]).is_none());
        let mut combined = vec![0xf0, 0xbc, 0x7c];
        combined.extend_from_slice(&encoded[2..]);
        assert_eq!(amr.decode(&combined).unwrap().len(), 2 * FRAME);
        Ok(())
    }
}
