use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, ensure};

const AMR_PT: u8 = 118;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Codec {
    Pcmu,
    Pcma,
    Amr { modes: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Audio {
    pub pt: u8,
    pub codec: Codec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Local,
    Upstream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Both,
    Send,
    Receive,
    Inactive,
}

impl Direction {
    fn parse(line: &str) -> Option<Self> {
        Some(match line {
            "a=sendrecv" => Self::Both,
            "a=sendonly" => Self::Send,
            "a=recvonly" => Self::Receive,
            "a=inactive" => Self::Inactive,
            _ => return None,
        })
    }

    fn reverse(self) -> &'static str {
        match self {
            Self::Both => "sendrecv",
            Self::Send => "recvonly",
            Self::Receive => "sendonly",
            Self::Inactive => "inactive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Description {
    pub remote: SocketAddr,
    pub audio: Audio,
    pub events: Option<u8>,
    direction: Direction,
    alternate_audio: Option<Audio>,
    answer_to_offer: bool,
}

impl Description {
    pub fn can_send(self) -> bool {
        matches!(self.direction, Direction::Send | Direction::Both)
    }

    pub fn can_receive(self) -> bool {
        matches!(self.direction, Direction::Receive | Direction::Both)
    }

    pub fn received_codec(self, pt: u8) -> Option<Codec> {
        let codecs = [Some(self.audio), self.alternate_audio];
        let audio = codecs.into_iter().flatten().find(|audio| audio.pt == pt);
        audio.map(|audio| audio.codec).or_else(|| {
            // An answer can assign a different payload number for the same codec.
            codecs.into_iter().flatten().find_map(|audio| {
                let offered_pt = match audio.codec {
                    Codec::Pcmu => 0,
                    Codec::Amr { .. } => AMR_PT,
                    Codec::Pcma => return None,
                };
                (self.answer_to_offer && offered_pt == pt).then_some(audio.codec)
            })
        })
    }

    pub fn parse(body: &[u8], side: Side, answer_to_offer: bool) -> Result<Self> {
        let sdp = std::str::from_utf8(body).context("invalid SDP text")?;
        ensure!(
            sdp.lines().next().is_some_and(|line| line.trim() == "v=0"),
            "missing SDP version"
        );
        let mut session_ip = None;
        let mut audio_ip = None;
        let mut session_direction = Direction::Both;
        let mut audio_direction = None;
        let mut audio = None;
        let mut rtpmap = HashMap::new();
        let mut fmtp = HashMap::new();
        let mut session = true;
        let mut in_audio = false;
        for line in sdp.lines().map(str::trim) {
            if let Some(media) = line.strip_prefix("m=") {
                if in_audio {
                    break;
                }
                session = false;
                if let Some(fields) = media.strip_prefix("audio ") {
                    let mut fields = fields.split_ascii_whitespace();
                    let port: u16 = fields.next().context("missing SDP audio port")?.parse()?;
                    ensure!(
                        port > 0 && fields.next() == Some("RTP/AVP"),
                        "unsupported SDP audio transport"
                    );
                    audio = Some((
                        port,
                        fields
                            .filter_map(|pt| pt.parse::<u8>().ok().filter(|pt| *pt < 128))
                            .collect::<Vec<_>>(),
                    ));
                    in_audio = true;
                }
            } else if let Some(connection) = line.strip_prefix("c=IN ") {
                let (family, ip) = connection
                    .split_once(' ')
                    .context("invalid SDP connection")?;
                if session || in_audio {
                    let ip: IpAddr = ip.trim().parse().context("invalid SDP connection IP")?;
                    ensure!(
                        matches!(
                            (family, ip),
                            ("IP4", IpAddr::V4(_)) | ("IP6", IpAddr::V6(_))
                        ),
                        "SDP address family mismatch"
                    );
                    if session {
                        session_ip = Some(ip);
                    } else {
                        audio_ip = Some(ip);
                    }
                }
            } else if let Some(direction) = Direction::parse(line) {
                if session {
                    session_direction = direction;
                } else if in_audio {
                    audio_direction = Some(direction);
                }
            } else if in_audio {
                for (prefix, values) in [("a=rtpmap:", &mut rtpmap), ("a=fmtp:", &mut fmtp)] {
                    if let Some((pt, value)) = line
                        .strip_prefix(prefix)
                        .and_then(|value| value.split_once(char::is_whitespace))
                        && let Ok(pt) = pt.parse::<u8>()
                    {
                        values.insert(pt, value.trim());
                    }
                }
            }
        }
        let (port, pts) = audio.context("SDP has no audio media")?;
        let ip = audio_ip.or(session_ip).context("SDP has no RTP address")?;
        ensure!(!ip.is_multicast(), "multicast RTP is unsupported");
        let direction = if ip.is_unspecified() {
            Direction::Inactive
        } else {
            audio_direction.unwrap_or(session_direction)
        };
        let remote = SocketAddr::new(ip, port);
        let mapped = |pt, codec| {
            rtpmap
                .get(&pt)
                .is_some_and(|value| mono_mapping(value, codec))
        };
        let events = pts.iter().copied().find(|pt| {
            *pt >= 96 && (!answer_to_offer || *pt == 101) && mapped(*pt, "telephone-event/8000")
        });
        let mut formats = pts.into_iter().filter_map(|pt| {
            let codec = match pt {
                0 if !rtpmap.contains_key(&pt) || mapped(pt, "PCMU/8000") => Codec::Pcmu,
                8 if side == Side::Upstream
                    && !answer_to_offer
                    && (!rtpmap.contains_key(&pt) || mapped(pt, "PCMA/8000")) =>
                {
                    Codec::Pcma
                }
                96..=127 if mapped(pt, "PCMU/8000") => Codec::Pcmu,
                96..=127 if side == Side::Upstream && mapped(pt, "AMR/8000") => Codec::Amr {
                    modes: amr_modes(fmtp.get(&pt).copied().unwrap_or_default())?,
                },
                _ => return None,
            };
            Some(Audio { pt, codec })
        });
        let audio = formats.next().context(match side {
            Side::Local => "local SDP has no supported PCMU audio format",
            Side::Upstream => "IMS SDP has no supported audio format",
        })?;
        // Our answer to an incoming offer advertises one codec. An answer to our
        // two-codec IMS offer can keep both and switch between them during the call.
        let alternate_audio = if side == Side::Upstream && answer_to_offer {
            formats.find(|other| {
                matches!(
                    (audio.codec, other.codec),
                    (Codec::Pcmu, Codec::Amr { .. }) | (Codec::Amr { .. }, Codec::Pcmu)
                )
            })
        } else {
            None
        };
        Ok(Self {
            remote,
            audio,
            events,
            direction,
            alternate_audio,
            answer_to_offer,
        })
    }

    pub fn answer(self, addr: SocketAddr) -> String {
        render(addr, &[self.audio], self.events, self.direction.reverse())
    }

    /// Answers a mid-dialog offer (UPDATE). The SDP version must increase within
    /// the session, and RFC 3312 precondition lines in the offer are mirrored with
    /// our side's resources reported as already reserved.
    pub fn answer_update(self, addr: SocketAddr, version: u32, offer: &[u8]) -> String {
        let mut sdp =
            self.answer(addr)
                .replacen("o=JioCall 1 1 ", &format!("o=JioCall 1 {version} "), 1);
        sdp.push_str(&precondition_answer(offer));
        sdp
    }
}

fn precondition_answer(offer: &[u8]) -> String {
    let mut lines = String::new();
    for line in String::from_utf8_lossy(offer).lines().map(str::trim) {
        let mirrored = if let Some(rest) = line.strip_prefix("a=curr:qos ") {
            match rest.split_once(' ') {
                Some(("local", direction)) => format!("a=curr:qos remote {direction}"),
                Some(("remote", _)) => "a=curr:qos local sendrecv".to_owned(),
                _ => line.to_owned(),
            }
        } else if let Some(rest) = line.strip_prefix("a=des:qos ") {
            let mut fields = rest.split_ascii_whitespace();
            match (fields.next(), fields.next(), fields.next()) {
                (Some(strength), Some("local"), Some(direction)) => {
                    format!("a=des:qos {strength} remote {direction}")
                }
                (Some(strength), Some("remote"), Some(direction)) => {
                    format!("a=des:qos {strength} local {direction}")
                }
                _ => line.to_owned(),
            }
        } else {
            continue;
        };
        lines.push_str(&mirrored);
        lines.push_str("\r\n");
    }
    lines
}

fn mono_mapping(mapping: &str, codec: &str) -> bool {
    if let Some(name) = mapping.strip_suffix("/1") {
        name.eq_ignore_ascii_case(codec)
    } else {
        mapping.eq_ignore_ascii_case(codec)
    }
}

fn amr_modes(fmtp: &str) -> Option<u8> {
    let mut octets = false;
    let mut modes = u8::MAX;
    for part in fmtp.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "octet-align" => octets = value.trim() == "1",
            "crc" | "robust-sorting" | "interleaving" if value.trim() != "0" => return None,
            "mode-set" => {
                modes = 0;
                for value in value.split(',') {
                    let value = value.trim().parse::<u8>().ok()?;
                    if value > 7 {
                        return None;
                    }
                    modes |= 1 << value;
                }
            }
            _ => {}
        }
    }
    (octets && modes != 0).then_some(modes)
}

pub fn offer(addr: SocketAddr, side: Side) -> String {
    let pcmu = Audio {
        pt: 0,
        codec: Codec::Pcmu,
    };
    let amr = Audio {
        pt: AMR_PT,
        codec: Codec::Amr { modes: u8::MAX },
    };
    let codecs = if side == Side::Upstream {
        &[amr, pcmu][..]
    } else {
        &[pcmu][..]
    };
    render(addr, codecs, Some(101), "sendrecv")
}

fn render(addr: SocketAddr, codecs: &[Audio], events: Option<u8>, direction: &str) -> String {
    use std::fmt::Write;
    let family = if addr.is_ipv6() { "IP6" } else { "IP4" };
    let ip = addr.ip();
    let mut sdp = format!(
        "v=0\r\no=JioCall 1 1 IN {family} {ip}\r\ns=-\r\nc=IN {family} {ip}\r\nt=0 0\r\nm=audio {} RTP/AVP",
        addr.port()
    );
    for audio in codecs {
        let _ = write!(sdp, " {}", audio.pt);
    }
    if let Some(pt) = events {
        let _ = write!(sdp, " {pt}");
    }
    sdp.push_str("\r\n");
    for Audio { pt, codec } in codecs {
        let name = match codec {
            Codec::Pcmu => "PCMU",
            Codec::Pcma => "PCMA",
            Codec::Amr { .. } => "AMR",
        };
        let _ = write!(sdp, "a=rtpmap:{pt} {name}/8000\r\n");
        if let Codec::Amr { modes } = codec {
            let _ = write!(sdp, "a=fmtp:{pt} octet-align=1");
            if *modes != u8::MAX {
                let modes = (0..8)
                    .filter(|mode| modes & (1 << mode) != 0)
                    .map(|mode| mode.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let _ = write!(sdp, "; mode-set={modes}");
            }
            sdp.push_str("\r\n");
        }
    }
    if let Some(pt) = events {
        let _ = write!(
            sdp,
            "a=rtpmap:{pt} telephone-event/8000\r\na=fmtp:{pt} 0-15\r\n"
        );
    }
    let _ = write!(sdp, "a={direction}\r\n");
    sdp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_pcmu_and_ims_amr_are_negotiated_independently() -> Result<()> {
        for pt in [0, 96] {
            let phone = format!(
                "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 1234 RTP/AVP 9 8 {pt}\r\na=rtpmap:9 G722/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:{pt} PCMU/8000/1\r\n"
            );
            let expected = Audio {
                pt,
                codec: Codec::Pcmu,
            };
            let local = Description::parse(phone.as_bytes(), Side::Local, false)?;
            assert_eq!(local.audio, expected);
            assert!(
                local
                    .answer("127.0.0.1:12000".parse()?)
                    .contains(&format!("m=audio 12000 RTP/AVP {pt}\r\n"))
            );
        }

        let offer = offer("[::1]:52000".parse()?, Side::Upstream);
        assert!(offer.contains("m=audio 52000 RTP/AVP 118 0 101\r\n"));
        assert!(offer.contains("a=fmtp:118 octet-align=1\r\n"));
        let ims = b"v=0\r\nc=IN IP6 ::1\r\nm=audio 6000 RTP/AVP 110 0\r\na=rtpmap:110 AMR/8000/1\r\na=fmtp:110 octet-align=1;mode-set=2\r\n";
        let parsed = Description::parse(ims, Side::Upstream, true)?;
        let amr = Codec::Amr { modes: 1 << 2 };
        assert_eq!(
            parsed.audio,
            Audio {
                pt: 110,
                codec: amr
            }
        );
        assert_eq!(parsed.received_codec(110), Some(amr));
        assert_eq!(parsed.received_codec(AMR_PT), Some(amr));
        assert_eq!(parsed.received_codec(0), Some(Codec::Pcmu));
        Ok(())
    }

    #[test]
    fn update_answer_bumps_version_and_meets_preconditions() -> Result<()> {
        let update = b"v=0\r\no=- 5 6 IN IP6 ::2\r\ns=-\r\nc=IN IP6 ::2\r\nt=0 0\r\nm=audio 7000 RTP/AVP 118 101\r\na=rtpmap:118 AMR/8000\r\na=fmtp:118 octet-align=1;mode-set=7\r\na=rtpmap:101 telephone-event/8000\r\na=curr:qos local sendrecv\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\na=des:qos mandatory remote sendrecv\r\na=sendrecv\r\n";
        let offer = Description::parse(update, Side::Upstream, false)?;
        assert_eq!(offer.remote, "[::2]:7000".parse()?);
        let answer = offer.answer_update("[::1]:52000".parse()?, 2, update);
        assert!(answer.contains("o=JioCall 1 2 IN IP6 ::1\r\n"));
        assert!(answer.contains("m=audio 52000 RTP/AVP 118 101\r\n"));
        for line in [
            "a=curr:qos remote sendrecv\r\n",
            "a=curr:qos local sendrecv\r\n",
            "a=des:qos mandatory remote sendrecv\r\n",
            "a=des:qos mandatory local sendrecv\r\n",
        ] {
            assert!(answer.contains(line), "missing {line:?} in {answer}");
        }
        let plain = b"v=0\r\nc=IN IP6 ::2\r\nm=audio 7000 RTP/AVP 0\r\n";
        let answer = Description::parse(plain, Side::Upstream, false)?.answer_update(
            "[::1]:52000".parse()?,
            3,
            plain,
        );
        assert!(!answer.contains("qos"));
        Ok(())
    }
}
