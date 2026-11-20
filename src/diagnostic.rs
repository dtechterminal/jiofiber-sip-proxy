use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    net::UdpSocket,
    sync::watch,
    time::{Instant, MissedTickBehavior, interval},
};

use crate::{
    config::{Network, SipConfig},
    invite::{Invitation, InviteEvent},
    rtp::{self, FRAME, Packet, Relay, Sequencer},
    sdp::{self, Description, Side},
    sip::{self, Frame, INVITE_TIMEOUT, Message},
    upstream::{Registration, Upstream},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Play {
    Wait,
    Early,
    Answered,
    Stop,
}

fn melody() -> Vec<u8> {
    let notes = [
        (523, 300),
        (523, 300),
        (784, 300),
        (784, 300),
        (880, 300),
        (880, 300),
        (784, 600),
        (698, 300),
        (698, 300),
        (659, 300),
        (659, 300),
        (587, 300),
        (587, 300),
        (523, 600),
    ];
    let mut audio = Vec::new();
    for (hz, ms) in notes {
        audio.extend((0..8 * ms).map(|i| {
            let phase = std::f64::consts::TAU * f64::from(hz * i) / 8000.0;
            rtp::pcm_to_ulaw((12800.0 * phase.sin()) as i16)
        }));
        audio.extend([0xff; FRAME]);
    }
    audio
}

async fn audio(
    socket: UdpSocket,
    relay: SocketAddr,
    mut play: watch::Receiver<Play>,
) -> Result<Vec<u8>> {
    let melody = melody();
    let melody_frames = melody.len() / FRAME;
    let mut ticks = interval(Duration::from_millis(20));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut mode = Play::Wait;
    let mut frame = 0;
    let mut ts = 0u32;
    let mut seq = Sequencer::new();
    let mut packet = [0; 4096];
    let mut recording = Vec::new();
    loop {
        tokio::select! {
            result = play.changed() => {
                if result.is_err() { return Ok(recording); }
                mode = *play.borrow_and_update();
                if mode == Play::Stop { return Ok(recording); }
                frame = 0;
            }
            received = socket.recv_from(&mut packet) => {
                let (len, peer) = received?;
                if recording.len() < 2_000_000 && peer == relay && let Some(packet) = Packet::parse(&packet[..len]) && packet.pt == 0 {
                    recording.extend(packet.payload.iter().flat_map(|&sample| rtp::ulaw_to_pcm(sample).to_le_bytes()));
                }
            }
            _ = ticks.tick() => {
                let second = melody_frames + 750;
                let index = match mode {
                    Play::Early | Play::Answered if frame < melody_frames => Some(frame),
                    Play::Answered if (second..second + melody_frames).contains(&frame) => Some(frame - second),
                    Play::Answered if frame >= second + melody_frames + 100 => return Ok(recording),
                    _ => None,
                };
                if let Some(index) = index {
                    let offset = index * FRAME;
                    let bytes = seq.packet(0, index == 0, ts, &melody[offset..offset + FRAME]);
                    socket.send_to(&bytes, relay).await?;
                }
                ts = ts.wrapping_add(FRAME as u32);
                frame += 1;
            }
        }
    }
}

async fn wav(path: &Path, mut pcm: Vec<u8>) -> Result<()> {
    let size = u32::try_from(pcm.len())?;
    let mut file = Vec::with_capacity(44 + pcm.len());
    file.extend_from_slice(b"RIFF");
    file.extend_from_slice(&(36 + size).to_le_bytes());
    file.extend_from_slice(b"WAVEfmt ");
    file.extend_from_slice(&16u32.to_le_bytes());
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&8000u32.to_le_bytes());
    file.extend_from_slice(&16000u32.to_le_bytes());
    file.extend_from_slice(&2u16.to_le_bytes());
    file.extend_from_slice(&16u16.to_le_bytes());
    file.extend_from_slice(b"data");
    file.extend_from_slice(&size.to_le_bytes());
    file.append(&mut pcm);
    tokio::fs::write(path, file)
        .await
        .context("writing call recording")
}

pub async fn call(
    cfg: &SipConfig,
    net: &Network,
    instance: &str,
    number: &str,
    recording: &Path,
) -> Result<()> {
    let target = sip::target_uri(number, cfg.domain())?;
    let mut upstream = Upstream::connect(cfg, net, instance).await?;
    let mut registration = Registration::new(cfg);
    registration.initial(cfg, &mut upstream).await?;
    let relay = Relay::bind(
        Ipv4Addr::LOCALHOST.into(),
        upstream.endpoint.addr.ip(),
        net.rtp_port,
    )
    .await?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let local = sdp::offer(socket.local_addr()?, Side::Local);
    relay.set(
        Side::Local,
        Description::parse(local.as_bytes(), Side::Local, false)?,
    )?;
    let (play, receive) = watch::channel(Play::Wait);
    let mut audio = Box::pin(audio(socket, relay.local, receive));
    let mut invite = Invitation::new(
        &upstream.endpoint,
        &cfg.public_id,
        &target,
        sdp::offer(relay.upstream, Side::Upstream),
        true,
    );
    upstream.send(&invite.request).await?;
    let mut ticks = interval(Duration::from_millis(100));
    let mut has_media = false;
    let mut answered = false;
    let mut cancelling = false;
    let mut deadline = Instant::now() + INVITE_TIMEOUT;
    let mut failure = None;
    let stop = crate::shutdown();
    tokio::pin!(stop);
    let mut saved = None;
    let mut remote_ended = false;
    let result = async {
        loop {
            tokio::select! {
                pcm = &mut audio => {
                    saved = Some(pcm);
                    break;
                }
                _ = &mut stop, if !cancelling => {
                    if answered { break; }
                    cancelling = true;
                    deadline = Instant::now() + Duration::from_secs(5);
                    if let Some(cancel) = invite.cancel() { upstream.send(&cancel).await?; }
                }
                now = ticks.tick() => {
                    if let Some(msg) = registration.tick(cfg, &upstream.endpoint, now)? { upstream.send(&msg).await?; }
                    if !answered && now >= deadline {
                        if cancelling { break; }
                        failure = Some(anyhow::anyhow!("INVITE timed out"));
                        cancelling = true;
                        deadline = now + Duration::from_secs(5);
                        if let Some(cancel) = invite.cancel() { upstream.send(&cancel).await?; }
                    }
                }
                frame = upstream.recv() => {
                    let msg = match frame? {
                        Frame::Ping => { upstream.pong().await?; continue; }
                        Frame::Message(msg) => msg,
                    };
                    if msg.status().is_some() && msg.cseq().is_some_and(|(_, method)| method == "REGISTER") {
                        if let Some(request) = registration.handle(cfg, &upstream.endpoint, &msg)? { upstream.send(&request).await?; }
                        continue;
                    }
                    if let Some(method) = msg.method() {
                        if !msg.valid_request() || method == "ACK" { continue; }
                        let dialog = invite.dialog.as_ref().is_some_and(|dialog| dialog.matches(&msg));
                        let (status, reason) = match (method, dialog) {
                            ("OPTIONS", _) | ("BYE", true) => (200, "OK"),
                            ("UPDATE", true) if msg.body.is_empty() => (200, "OK"),
                            ("INVITE" | "UPDATE", true) => (488, "Not Acceptable Here"),
                            _ => (481, "Call/Transaction Does Not Exist"),
                        };
                        upstream.send(&Message::response(&msg, status, reason, Some(&sip::id()))).await?;
                        if method == "BYE" && dialog { remote_ended = true; break; }
                        continue;
                    }
                    let (event, requests) = invite.handle(&msg, Some(cfg))?;
                    for request in requests { upstream.send(&request).await?; }
                    match event {
                        InviteEvent::Progress(code) if code > 100 && !msg.body.is_empty() && !answered && !cancelling => {
                            if let Ok(remote) = Description::parse(&msg.body, Side::Upstream, true) && relay.set(Side::Upstream, remote).is_ok() {
                                has_media = true;
                                play.send_if_modified(|state| {
                                    if *state == Play::Wait { *state = Play::Early; true } else { false }
                                });
                            }
                        }
                        InviteEvent::Retry => {
                            relay.clear(Side::Upstream);
                            has_media = false;
                            let _ = play.send(Play::Wait);
                        }
                        InviteEvent::Answer => {
                            if cancelling { break; }
                            if !msg.body.is_empty() {
                                relay.set(Side::Upstream, Description::parse(&msg.body, Side::Upstream, true)?)?;
                                has_media = true;
                            }
                            ensure!(has_media, "no RTP session established");
                            answered = true;
                            eprintln!("Call answered, playing test melody and recording audio");
                            let _ = play.send(Play::Answered);
                        }
                        InviteEvent::Reject(code) if !cancelling => bail!("INVITE failed with SIP {code}"),
                        InviteEvent::Reject(_) => break,
                        _ => {}
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;
    if !remote_ended && let Some(bye) = invite.bye() {
        let _ = upstream.send(&bye).await;
    }
    let pcm = if let Some(pcm) = saved {
        pcm?
    } else {
        let _ = play.send(Play::Stop);
        audio.await?
    };
    relay.stop().await;
    if !pcm.is_empty() {
        wav(recording, pcm).await?;
        eprintln!("Recording saved to {}", recording.display());
    }
    if let Some(error) = failure {
        return Err(error);
    }
    result
}
