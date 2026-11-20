use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    net::{UdpSocket, lookup_host},
    time::{Instant, interval, sleep, timeout},
};

use crate::{
    config::{Network, SipConfig},
    invite::{Invitation, InviteEvent},
    rtp::Relay,
    sdp::{self, Description, Side},
    sip::{self, Dialog, Endpoint, Frame, INVITE_TIMEOUT, Message, TRANSACTION},
    upstream::{ALLOW, Registration, Upstream},
};

const T1: Duration = Duration::from_millis(500);
const T2: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Peer {
    Local(SocketAddr),
    Upstream,
}

impl Peer {
    fn side(self) -> Side {
        match self {
            Self::Local(_) => Side::Local,
            Self::Upstream => Side::Upstream,
        }
    }
}

struct Delivery {
    peer: Peer,
    msg: Message,
}

impl Delivery {
    fn new(peer: Peer, msg: Message) -> Self {
        Self { peer, msg }
    }
}

struct Resend {
    next: Instant,
    interval: Duration,
}

impl Resend {
    fn new() -> Self {
        Self {
            next: Instant::now() + T1,
            interval: T1,
        }
    }

    fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.interval = (self.interval * 2).min(T2);
        self.next = now + self.interval;
        true
    }
}

struct ServerReply {
    peer: Peer,
    request: Message,
    msg: Message,
    resend: Option<Resend>,
    expires: Instant,
}

impl ServerReply {
    fn matches_ack(&self, peer: Peer, ack: &Message) -> bool {
        self.request.method() == Some("INVITE")
            && ack.method() == Some("ACK")
            && peer == self.peer
            && ack.header("Call-ID") == self.msg.header("Call-ID")
            && ack
                .header("From")
                .and_then(|value| sip::parameter(value, "tag"))
                == self
                    .msg
                    .header("From")
                    .and_then(|value| sip::parameter(value, "tag"))
            && ack
                .header("To")
                .and_then(|value| sip::parameter(value, "tag"))
                == self
                    .msg
                    .header("To")
                    .and_then(|value| sip::parameter(value, "tag"))
            && ack.cseq().map(|(seq, _)| seq) == self.msg.cseq().map(|(seq, _)| seq)
            && (self.msg.status().is_some_and(|(status, _)| status < 300)
                || ack.via_branch() == self.request.via_branch())
    }
}

struct ClientRetry {
    peer: Peer,
    msg: Message,
    resend: Resend,
    expires: Instant,
    paused: bool,
}

struct Tail {
    peer: Peer,
    invitation: Invitation,
    expires: Instant,
}

struct Destination {
    uri: Option<String>,
    addr: SocketAddr,
}

impl Destination {
    async fn resolve(value: &str, family: IpAddr) -> Result<Self> {
        ensure!(
            !value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '<' | '>')),
            "invalid DEST_TO_LOCAL"
        );
        let (uri, host) = if let Some(uri) = value.strip_prefix("sip:") {
            let (_, host) = uri
                .rsplit_once('@')
                .context("DEST_TO_LOCAL SIP URI requires a user and host")?;
            (
                Some(value.to_owned()),
                host.split(';').next().unwrap_or(host),
            )
        } else {
            (None, value)
        };
        let (host, port) = sip::host_port(host, 5060)?;
        let addr = timeout(Duration::from_secs(5), lookup_host((host, port)))
            .await?
            .context("resolving DEST_TO_LOCAL")?
            .find(|addr| addr.is_ipv6() == family.is_ipv6())
            .context("DEST_TO_LOCAL has no address in the LOCAL_BIND family")?;
        Ok(Self { uri, addr })
    }

    fn uri(&self, user: &str) -> String {
        self.uri
            .clone()
            .unwrap_or_else(|| format!("sip:{user}@{}", self.addr))
    }
}

struct Reliable {
    rack: String,
    msg: Message,
    resend: Resend,
    expires: Instant,
}

struct Call {
    origin: Peer,
    peer: Peer,
    incoming: Message,
    to_tag: String,
    incoming_dialog: Dialog,
    incoming_media: Description,
    invitation: Invitation,
    media: Relay,
    local_rtp: SocketAddr,
    last_reply: Message,
    reliable: Option<Reliable>,
    next_rseq: u32,
    peer_media: bool,
    answer_waiting: bool,
    answer_acked: bool,
    sdp_version: u32,
    deadline: Instant,
}

impl Call {
    fn established(&self) -> bool {
        self.last_reply
            .status()
            .is_some_and(|(status, _)| (200..300).contains(&status))
    }

    fn media_addr(&self, peer: Peer) -> SocketAddr {
        if peer == Peer::Upstream {
            self.media.upstream
        } else {
            self.local_rtp
        }
    }

    fn set_media(&self, message: &Message) -> Result<()> {
        let media = Description::parse(&message.body, self.peer.side(), true)?;
        self.media.set(self.peer.side(), media)
    }
}

pub struct Bridge<'a> {
    cfg: &'a SipConfig,
    net: &'a Network,
    local: Endpoint,
    ims: Endpoint,
    destination: Option<&'a Destination>,
    active: Option<Call>,
    server: VecDeque<ServerReply>,
    client: Vec<ClientRetry>,
    tails: VecDeque<Tail>,
}

impl<'a> Bridge<'a> {
    fn new(
        cfg: &'a SipConfig,
        net: &'a Network,
        local: Endpoint,
        ims: Endpoint,
        destination: Option<&'a Destination>,
    ) -> Self {
        Self {
            cfg,
            net,
            local,
            ims,
            destination,
            active: None,
            server: VecDeque::new(),
            client: Vec::new(),
            tails: VecDeque::new(),
        }
    }

    fn endpoint(&self, peer: Peer) -> &Endpoint {
        if peer == Peer::Upstream {
            &self.ims
        } else {
            &self.local
        }
    }

    fn emit(&mut self, peer: Peer, msg: Message, out: &mut Vec<Delivery>) {
        if matches!(peer, Peer::Local(_))
            && matches!(msg.method(), Some("INVITE" | "BYE" | "CANCEL" | "PRACK"))
            && !self
                .client
                .iter()
                .any(|entry| entry.peer == peer && entry.msg.transaction_matches(&msg))
        {
            let expiry = if msg.method() == Some("INVITE") {
                INVITE_TIMEOUT
            } else {
                TRANSACTION
            };
            self.client.push(ClientRetry {
                peer,
                msg: msg.clone(),
                resend: Resend::new(),
                expires: Instant::now() + expiry,
                paused: false,
            });
        }
        out.push(Delivery::new(peer, msg));
    }

    fn reply(&mut self, peer: Peer, req: &Message, msg: Message, out: &mut Vec<Delivery>) {
        let status = msg.status().map_or(0, |(code, _)| code);
        if status >= 200 {
            if self.server.len() == 128 {
                self.server.pop_front();
            }
            let resend = (req.method() == Some("INVITE")
                && (matches!(peer, Peer::Local(_)) || status < 300))
                .then(Resend::new);
            self.server.push_back(ServerReply {
                peer,
                request: req.clone(),
                msg: msg.clone(),
                resend,
                expires: Instant::now() + TRANSACTION,
            });
        }
        out.push(Delivery::new(peer, msg));
    }

    fn simple(
        &mut self,
        peer: Peer,
        req: &Message,
        status: u16,
        reason: &str,
        out: &mut Vec<Delivery>,
    ) {
        self.reply(
            peer,
            req,
            Message::response(req, status, reason, Some(&sip::id())),
            out,
        );
    }

    fn uas_response(&self, call: &Call, status: u16, reason: &str, with_media: bool) -> Message {
        let mut msg = Message::response(&call.incoming, status, reason, Some(&call.to_tag));
        if (101..300).contains(&status) {
            msg.add("Contact", &self.endpoint(call.origin).contact);
            msg.add("Allow", ALLOW);
            if with_media {
                msg.set_sdp(call.incoming_media.answer(call.media_addr(call.origin)));
            }
        }
        msg
    }

    fn final_reply(&mut self, call: &mut Call, status: u16, reason: &str, out: &mut Vec<Delivery>) {
        let reply = self.uas_response(call, status, reason, (200..300).contains(&status));
        call.last_reply = reply.clone();
        call.deadline = Instant::now() + TRANSACTION;
        self.reply(call.origin, &call.incoming, reply, out);
    }

    fn retire(&mut self, call: Call) -> Relay {
        if self.tails.len() == 32 {
            self.tails.pop_front();
        }
        self.tails.push_back(Tail {
            peer: call.peer,
            invitation: call.invitation,
            expires: Instant::now() + TRANSACTION,
        });
        call.media
    }

    async fn start_call(&self, origin: Peer, req: &Message) -> Result<Call> {
        let user = req
            .uri()
            .and_then(uri_user)
            .context("INVITE URI has no destination user")?;
        let (peer, target, from) = if origin == Peer::Upstream {
            let destination = self.destination.context("no inbound call destination")?;
            let caller = req
                .header("From")
                .and_then(sip::uri_from_header)
                .and_then(uri_user)
                .filter(|user| {
                    user.bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || b"+-_.%".contains(&ch))
                })
                .unwrap_or("anonymous");
            (
                Peer::Local(destination.addr),
                destination.uri(user),
                format!("sip:{caller}@{}", self.local.addr),
            )
        } else {
            (
                Peer::Upstream,
                sip::target_uri(user, self.cfg.domain())?,
                self.cfg.public_id.clone(),
            )
        };
        let incoming_media = Description::parse(&req.body, origin.side(), false)?;
        let media = Relay::bind(self.net.bind, self.ims.addr.ip(), self.net.rtp_port).await?;
        media.set(origin.side(), incoming_media)?;
        let local_rtp = SocketAddr::new(self.local.addr.ip(), media.local.port());
        let rtp = if peer == Peer::Upstream {
            media.upstream
        } else {
            local_rtp
        };
        let invitation = Invitation::new(
            self.endpoint(peer),
            &from,
            &target,
            sdp::offer(rtp, peer.side()),
            peer == Peer::Upstream,
        );
        let to_tag = sip::id();
        let incoming_dialog = Dialog::incoming(req, &to_tag);
        let last_reply = Message::response(req, 100, "Trying", None);
        Ok(Call {
            origin,
            peer,
            incoming: req.clone(),
            to_tag,
            incoming_dialog,
            incoming_media,
            invitation,
            media,
            local_rtp,
            last_reply,
            reliable: None,
            next_rseq: (uuid::Uuid::new_v4().as_u128() >> 96) as u32 % 0x7fff_0000 + 1,
            peer_media: false,
            answer_waiting: false,
            answer_acked: false,
            sdp_version: 1,
            deadline: Instant::now() + INVITE_TIMEOUT,
        })
    }

    async fn request(&mut self, peer: Peer, req: Message, out: &mut Vec<Delivery>) {
        if !req.valid_request() {
            return;
        }
        if let Some(reply) = self
            .server
            .iter()
            .find(|entry| entry.peer == peer && req.transaction_matches(&entry.request))
        {
            out.push(Delivery::new(peer, reply.msg.clone()));
            return;
        }
        let method = req.method().unwrap_or_default();
        if matches!(peer, Peer::Local(_)) && method == "REGISTER" {
            self.reply(peer, &req, local_register_response(&req), out);
            return;
        }
        if method == "ACK" {
            for reply in &mut self.server {
                if reply.matches_ack(peer, &req) {
                    reply.resend = None;
                }
            }
        }
        let Some(mut call) = self.active.take() else {
            if method == "INVITE"
                && req
                    .header("To")
                    .and_then(|to| sip::parameter(to, "tag"))
                    .is_none()
            {
                if peer == Peer::Upstream && self.destination.is_none() {
                    self.simple(peer, &req, 480, "Temporarily Unavailable", out);
                } else if let Some(require) = req
                    .values("Require")
                    .flat_map(|value| value.split(','))
                    .map(str::trim)
                    .find(|value| !value.eq_ignore_ascii_case("100rel"))
                {
                    let tag = sip::id();
                    let mut message = Message::response(&req, 420, "Bad Extension", Some(&tag));
                    message.add("Unsupported", require);
                    self.reply(peer, &req, message, out);
                } else {
                    match self.start_call(peer, &req).await {
                        Ok(call) => {
                            out.push(Delivery::new(peer, call.last_reply.clone()));
                            self.emit(call.peer, call.invitation.request.clone(), out);
                            self.active = Some(call);
                        }
                        Err(error) => {
                            eprintln!("Cannot start call: {error}");
                            self.simple(peer, &req, 488, "Not Acceptable Here", out);
                        }
                    }
                }
            } else {
                self.outside_dialog(peer, &req, out);
            }
            return;
        };
        let origin_dialog = peer == call.origin && call.incoming_dialog.matches(&req);
        let other_dialog = peer == call.peer
            && call
                .invitation
                .dialog
                .as_ref()
                .is_some_and(|dialog| dialog.matches(&req));
        // Before the 2xx, IMS can send in-dialog requests (UPDATE) on an early
        // dialog, which `invitation.dialog` does not track yet.
        let early_dialog = peer == call.peer
            && call.invitation.dialog.is_none()
            && req.header("Call-ID") == call.invitation.request.header("Call-ID")
            && req
                .header("From")
                .and_then(|from| sip::parameter(from, "tag"))
                .is_some()
            && req.header("To").and_then(|to| sip::parameter(to, "tag"))
                == call
                    .invitation
                    .request
                    .header("From")
                    .and_then(|from| sip::parameter(from, "tag"));
        let same_invite = peer == call.origin
            && req.header("Call-ID") == call.incoming.header("Call-ID")
            && req.header("From") == call.incoming.header("From")
            && req.via_branch() == call.incoming.via_branch()
            && req.cseq().map(|(seq, _)| seq) == call.incoming.cseq().map(|(seq, _)| seq);
        let finish = match method {
            "INVITE" if same_invite => {
                out.push(Delivery::new(peer, call.last_reply.clone()));
                false
            }
            "ACK" => {
                if origin_dialog
                    && call.established()
                    && req.cseq().map(|(seq, _)| seq) == call.incoming.cseq().map(|(seq, _)| seq)
                {
                    call.answer_acked = true;
                }
                false
            }
            "CANCEL" if same_invite => {
                self.simple(peer, &req, 200, "OK", out);
                if call.established() {
                    false
                } else {
                    if let Some(msg) = call.invitation.cancel().or_else(|| call.invitation.bye()) {
                        self.emit(call.peer, msg, out);
                    }
                    self.final_reply(&mut call, 487, "Request Terminated", out);
                    true
                }
            }
            "PRACK"
                if origin_dialog
                    && call.reliable.as_ref().is_some_and(|rel| {
                        req.header("RAck").is_some_and(|rack| {
                            rack.split_ascii_whitespace()
                                .eq(rel.rack.split_ascii_whitespace())
                        })
                    }) =>
            {
                call.reliable = None;
                self.simple(peer, &req, 200, "OK", out);
                if call.answer_waiting {
                    call.answer_waiting = false;
                    self.final_reply(&mut call, 200, "OK", out);
                }
                false
            }
            "BYE" if origin_dialog || other_dialog => {
                self.simple(peer, &req, 200, "OK", out);
                if origin_dialog {
                    if let Some(msg) = call.invitation.bye().or_else(|| call.invitation.cancel()) {
                        self.emit(call.peer, msg, out);
                    }
                } else if call.established() {
                    let bye = call
                        .incoming_dialog
                        .next_request(self.endpoint(call.origin), "BYE");
                    self.emit(call.origin, bye, out);
                }
                if !call.established() {
                    self.final_reply(&mut call, 487, "Request Terminated", out);
                }
                true
            }
            "UPDATE" if origin_dialog || other_dialog || early_dialog => {
                if req.body.is_empty() {
                    self.simple(peer, &req, 200, "OK", out);
                } else {
                    self.update_offer(&mut call, peer, &req, out);
                }
                false
            }
            "INVITE" if origin_dialog || other_dialog => {
                self.simple(peer, &req, 488, "Not Acceptable Here", out);
                false
            }
            "INVITE" => {
                self.simple(peer, &req, 486, "Busy Here", out);
                false
            }
            _ => {
                self.outside_dialog(peer, &req, out);
                false
            }
        };
        if finish {
            self.retire(call).stop().await;
        } else {
            self.active = Some(call);
        }
    }

    /// IMS sends UPDATE with SDP during early dialogs, for example to confirm
    /// QoS preconditions on VoLTE-to-VoLTE calls. Rejecting it makes IMS fail
    /// the INVITE, so answer the offer and follow any media change.
    fn update_offer(
        &mut self,
        call: &mut Call,
        peer: Peer,
        req: &Message,
        out: &mut Vec<Delivery>,
    ) {
        let media = Description::parse(&req.body, peer.side(), false)
            .and_then(|media| call.media.set(peer.side(), media).map(|()| media));
        let media = match media {
            Ok(media) => media,
            Err(error) => {
                eprintln!("Rejecting UPDATE offer: {error}");
                self.simple(peer, req, 488, "Not Acceptable Here", out);
                return;
            }
        };
        call.sdp_version += 1;
        let mut reply = Message::response(req, 200, "OK", None);
        reply.add("Contact", &self.endpoint(peer).contact);
        reply.add("Allow", ALLOW);
        reply.set_sdp(media.answer_update(call.media_addr(peer), call.sdp_version, &req.body));
        self.reply(peer, req, reply, out);
    }

    fn outside_dialog(&mut self, peer: Peer, req: &Message, out: &mut Vec<Delivery>) {
        let allow = || {
            if peer == Peer::Upstream {
                ALLOW.to_owned()
            } else {
                format!("{ALLOW}, REGISTER")
            }
        };
        match req.method() {
            Some("ACK") => {}
            Some("OPTIONS") => {
                let mut reply = Message::response(req, 200, "OK", Some(&sip::id()));
                reply.add("Allow", allow());
                reply.add("Supported", "100rel");
                self.reply(peer, req, reply, out);
            }
            Some("BYE" | "CANCEL" | "PRACK" | "UPDATE" | "INVITE") => {
                self.simple(peer, req, 481, "Call/Transaction Does Not Exist", out)
            }
            _ => {
                let mut reply = Message::response(req, 405, "Method Not Allowed", Some(&sip::id()));
                reply.add("Allow", allow());
                self.reply(peer, req, reply, out);
            }
        }
    }

    async fn response(&mut self, peer: Peer, msg: Message, out: &mut Vec<Delivery>) {
        let Some((status, reason)) = msg.status() else {
            return;
        };
        self.client.retain_mut(|entry| {
            if peer != entry.peer || !msg.transaction_matches(&entry.msg) {
                return true;
            }
            entry.paused = status < 200 && entry.msg.method() == Some("INVITE");
            status < 200
        });
        let cfg = (peer == Peer::Upstream).then_some(self.cfg);
        if let Some(tail) = self.tails.iter_mut().find(|tail| {
            tail.peer == peer && msg.header("Call-ID") == tail.invitation.request.header("Call-ID")
        }) {
            if let Ok((event, mut messages)) = tail.invitation.handle(&msg, cfg) {
                if matches!(event, InviteEvent::Answer) {
                    messages.extend(tail.invitation.bye());
                }
                for message in messages {
                    self.emit(peer, message, out);
                }
            }
            return;
        }
        let Some(mut call) = self.active.take() else {
            return;
        };
        if peer != call.peer {
            self.active = Some(call);
            return;
        }
        let mut finish = false;
        match call.invitation.handle(&msg, cfg) {
            Ok((event, messages)) => {
                for message in messages {
                    self.emit(peer, message, out);
                }
                match event {
                    InviteEvent::Progress(code)
                        if code > 100 && !call.established() && !call.invitation.cancelled() =>
                    {
                        let has_media = !msg.body.is_empty() && call.set_media(&msg).is_ok();
                        // After IMS early media (183 with SDP, e.g. operator ringback),
                        // a bare 180 would make the phone add its own ringback tone on
                        // top. Keep presenting early media instead.
                        let early = call.peer_media && !has_media && code == 180;
                        call.peer_media |= has_media;
                        let (code, reason, with_media) = if early {
                            (183, "Session Progress", true)
                        } else {
                            (code, reason, has_media)
                        };
                        if call.reliable.is_none()
                            && (call.last_reply.status().map(|(status, _)| status) != Some(code)
                                || call.last_reply.body.is_empty() == with_media)
                        {
                            let mut reply = self.uas_response(&call, code, reason, with_media);
                            if call.incoming.has_option("Require", "100rel") {
                                let seq = call.incoming.cseq().map_or(1, |(seq, _)| seq);
                                reply.add("Require", "100rel");
                                let rseq = call.next_rseq;
                                call.next_rseq += 1;
                                reply.add("RSeq", rseq.to_string());
                                call.reliable = Some(Reliable {
                                    rack: format!("{rseq} {seq} INVITE"),
                                    msg: reply.clone(),
                                    resend: Resend::new(),
                                    expires: Instant::now() + TRANSACTION,
                                });
                            }
                            call.last_reply = reply.clone();
                            out.push(Delivery::new(call.origin, reply));
                        }
                    }
                    InviteEvent::Retry => {
                        call.media.clear(peer.side());
                        call.peer_media = false;
                    }
                    InviteEvent::Answer => {
                        let valid = if msg.body.is_empty() {
                            call.peer_media
                        } else {
                            call.set_media(&msg).is_ok()
                        };
                        if !valid {
                            if let Some(bye) = call.invitation.bye() {
                                self.emit(peer, bye, out);
                            }
                            self.final_reply(&mut call, 488, "Not Acceptable Here", out);
                            finish = true;
                        } else if call.reliable.is_some() {
                            call.answer_waiting = true;
                        } else {
                            self.final_reply(&mut call, 200, "OK", out);
                        }
                    }
                    InviteEvent::Reject(code) => {
                        let (status, reason) = match code {
                            300..=399 => (480, "Temporarily Unavailable"),
                            401 | 407 => (502, "Bad Gateway"),
                            _ => (code, reason),
                        };
                        self.final_reply(&mut call, status, reason, out);
                        finish = true;
                    }
                    _ => {}
                }
            }
            Err(error) => eprintln!("Ignoring invalid INVITE response: {error}"),
        }
        if finish {
            self.retire(call).stop().await;
        } else {
            self.active = Some(call);
        }
    }

    async fn handle(&mut self, peer: Peer, msg: Message) -> Vec<Delivery> {
        let mut out = Vec::new();
        if msg.method().is_some() {
            self.request(peer, msg, &mut out).await;
        } else {
            self.response(peer, msg, &mut out).await;
        }
        out
    }

    async fn tick(&mut self, now: Instant) -> Vec<Delivery> {
        let mut out = Vec::new();
        self.server.retain_mut(|entry| {
            if now >= entry.expires {
                return false;
            }
            if entry.resend.as_mut().is_some_and(|retry| retry.due(now)) {
                out.push(Delivery::new(entry.peer, entry.msg.clone()));
            }
            true
        });
        self.client.retain_mut(|entry| {
            if now >= entry.expires {
                return false;
            }
            if !entry.paused && entry.resend.due(now) {
                out.push(Delivery::new(entry.peer, entry.msg.clone()));
            }
            true
        });
        self.tails.retain(|tail| now < tail.expires);
        if let Some(mut call) = self.active.take() {
            let reliable_timeout = call
                .reliable
                .as_ref()
                .is_some_and(|entry| now >= entry.expires);
            if (!call.established() || !call.answer_acked)
                && (now >= call.deadline || reliable_timeout)
            {
                if let Some(msg) = call.invitation.bye().or_else(|| call.invitation.cancel()) {
                    self.emit(call.peer, msg, &mut out);
                }
                if call.established() {
                    let bye = call
                        .incoming_dialog
                        .next_request(self.endpoint(call.origin), "BYE");
                    self.emit(call.origin, bye, &mut out);
                } else {
                    self.final_reply(&mut call, 504, "Server Time-out", &mut out);
                }
                self.retire(call).stop().await;
            } else {
                if let Some(reliable) = &mut call.reliable
                    && reliable.resend.due(now)
                {
                    out.push(Delivery::new(call.origin, reliable.msg.clone()));
                }
                self.active = Some(call);
            }
        }
        out
    }

    async fn disconnect(&mut self, udp: &UdpSocket, upstream: Option<&mut Upstream>) {
        if let Some(mut call) = self.active.take() {
            let local = if call.origin == Peer::Upstream {
                call.peer
            } else {
                call.origin
            };
            let message = if call.origin == Peer::Upstream {
                call.invitation.bye().or_else(|| call.invitation.cancel())
            } else if call.established() {
                Some(call.incoming_dialog.next_request(&self.local, "BYE"))
            } else {
                Some(self.uas_response(&call, 503, "Service Unavailable", false))
            };
            if let (Peer::Local(addr), Some(message)) = (local, message) {
                let _ = udp.send_to(&message.encode(), addr).await;
            }
            if let Some(upstream) = upstream {
                let message = if matches!(call.origin, Peer::Local(_)) {
                    call.invitation.bye().or_else(|| call.invitation.cancel())
                } else if call.established() {
                    Some(call.incoming_dialog.next_request(&self.ims, "BYE"))
                } else {
                    Some(self.uas_response(&call, 503, "Service Unavailable", false))
                };
                if let Some(message) = message {
                    let _ = upstream.send(&message).await;
                }
            }
            call.media.stop().await;
        }
    }
}

fn uri_user(uri: &str) -> Option<&str> {
    let user = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?
        .split_once('@')?
        .0;
    (!user.is_empty()
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-_.%*#".contains(&byte)))
    .then_some(user)
}

async fn dispatch(
    udp: &UdpSocket,
    upstream: &mut Upstream,
    deliveries: Vec<Delivery>,
) -> Result<()> {
    for delivery in deliveries {
        match delivery.peer {
            Peer::Local(peer) => {
                if let Err(error) = udp.send_to(&delivery.msg.encode(), peer).await {
                    eprintln!("Local SIP send failed: {error}");
                }
            }
            Peer::Upstream => upstream.send(&delivery.msg).await?,
        }
    }
    Ok(())
}

async fn drive(
    udp: &UdpSocket,
    bridge: &mut Bridge<'_>,
    upstream: &mut Upstream,
    reg: &mut Registration,
) -> Result<()> {
    let mut buffer = vec![0; 65_536];
    let mut ticks = interval(Duration::from_millis(100));
    loop {
        let deliveries = tokio::select! {
            received = udp.recv_from(&mut buffer) => {
                let (len, addr) = received?;
                if &buffer[..len] == b"\r\n\r\n" {
                    let _ = udp.send_to(b"\r\n", addr).await;
                    continue;
                }
                let Ok(mut msg) = Message::datagram(&buffer[..len]) else { continue; };
                if msg.method().is_some() { msg.apply_rport(addr); }
                bridge.handle(Peer::Local(addr), msg).await
            }
            frame = upstream.recv() => match frame? {
                Frame::Ping => { upstream.pong().await?; continue; }
                Frame::Message(msg) => {
                    if msg.status().is_some() && msg.cseq().is_some_and(|(_, method)| method == "REGISTER") {
                        if let Some(request) = reg.handle(bridge.cfg, &upstream.endpoint, &msg)? { upstream.send(&request).await?; }
                        continue;
                    }
                    bridge.handle(Peer::Upstream, msg).await
                }
            },
            now = ticks.tick() => {
                if let Some(request) = reg.tick(bridge.cfg, &upstream.endpoint, now)? { upstream.send(&request).await?; }
                bridge.tick(now).await
            }
        };
        dispatch(udp, upstream, deliveries).await?;
    }
}

async fn establish(
    cfg: &SipConfig,
    net: &Network,
    instance: &str,
    delay: Duration,
) -> Result<(Upstream, Registration)> {
    sleep(delay).await;
    let mut upstream = Upstream::connect(cfg, net, instance).await?;
    let mut registration = Registration::new(cfg);
    registration.initial(cfg, &mut upstream).await?;
    Ok((upstream, registration))
}

async fn offline(udp: &UdpSocket) -> Result<()> {
    let mut bytes = vec![0; 65_536];
    loop {
        let (len, addr) = udp.recv_from(&mut bytes).await?;
        if let Ok(mut msg) = Message::datagram(&bytes[..len])
            && msg.method() != Some("ACK")
            && msg.valid_request()
        {
            msg.apply_rport(addr);
            let response = if msg.method() == Some("REGISTER") {
                local_register_response(&msg)
            } else {
                let tag = sip::id();
                let mut response = Message::response(&msg, 503, "Service Unavailable", Some(&tag));
                response.add("Retry-After", "5");
                response
            };
            let _ = udp.send_to(&response.encode(), addr).await;
        }
    }
}

fn local_register_response(req: &Message) -> Message {
    let mut response = Message::response(req, 200, "OK", Some(&sip::id()));
    let default_expiry = req
        .header("Expires")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(3600);
    for contact in req.values("Contact").flat_map(sip::header_list) {
        if sip::uri_from_header(contact).is_none() {
            continue;
        }
        match sip::parameter(contact, "expires") {
            Some(value) if value.parse::<u32>().is_ok_and(|seconds| seconds > 0) => {
                response.add("Contact", contact);
            }
            None if default_expiry > 0 => {
                response.add("Contact", format!("{contact};expires={default_expiry}"));
            }
            _ => {}
        }
    }
    response
}

pub async fn serve(cfg: &SipConfig, net: &Network, instance: &str) -> Result<()> {
    let advertise = net.advertise.unwrap_or(net.bind);
    ensure!(
        !advertise.is_unspecified() && advertise.is_ipv6() == net.bind.is_ipv6(),
        "LOCAL_ADVERTISE_IP must be a concrete address in the LOCAL_BIND family"
    );
    let udp = UdpSocket::bind((net.bind, net.local_port))
        .await
        .context("binding local SIP/UDP")?;
    let addr = SocketAddr::new(advertise, udp.local_addr()?.port());
    let local = Endpoint {
        addr,
        transport: "UDP",
        contact: format!("<sip:bridge@{addr};transport=udp>"),
    };
    let destination = match &net.destination {
        Some(value) => Some(Destination::resolve(value, net.bind).await?),
        None => None,
    };
    eprintln!("Local SIP/UDP listening at {}", udp.local_addr()?);
    let shut_down = crate::shutdown();
    tokio::pin!(shut_down);
    let mut delay = Duration::ZERO;
    loop {
        let result = tokio::select! {
            _ = &mut shut_down => return Ok(()),
            result = establish(cfg, net, instance, delay) => result,
            result = offline(&udp) => return result,
        };
        delay = Duration::from_secs(5);
        match result {
            Ok((mut upstream, mut registration)) => {
                eprintln!("Registered with upstream SIP proxy");
                let mut bridge = Bridge::new(
                    cfg,
                    net,
                    local.clone(),
                    upstream.endpoint.clone(),
                    destination.as_ref(),
                );
                tokio::select! {
                    _ = &mut shut_down => {
                        bridge.disconnect(&udp, Some(&mut upstream)).await;
                        return Ok(());
                    }
                    result = drive(&udp, &mut bridge, &mut upstream, &mut registration) => {
                        if let Err(error) = result { eprintln!("Upstream SIP session ended: {error:#}"); }
                        bridge.disconnect(&udp, None).await;
                    }
                }
            }
            Err(error) => eprintln!("Upstream SIP registration failed: {error:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_register_returns_contact_expiry_while_ims_is_offline() -> Result<()> {
        let bridge = UdpSocket::bind("127.0.0.1:0").await?;
        let phone = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = phone.local_addr()?;
        let endpoint = Endpoint {
            addr,
            transport: "UDP",
            contact: format!("<sip:desk@{addr}>"),
        };
        let mut register = endpoint.request(
            "REGISTER",
            "sip:bridge.test",
            "<sip:desk@bridge.test>;tag=desk",
            "<sip:desk@bridge.test>",
            "register-test",
            1,
        );
        register.add(
            "Contact",
            format!(
                r#""Desk, East" {};maddr=127.0.0.1, <sip:old@{addr}>;expires=0"#,
                endpoint.contact
            ),
        );
        register.add("Expires", "120");
        phone
            .send_to(&register.encode(), bridge.local_addr()?)
            .await?;
        let mut bytes = [0; 2048];
        let mut service = std::pin::pin!(offline(&bridge));
        let response = tokio::select! {
            result = &mut service => {
                result?;
                anyhow::bail!("offline bridge stopped");
            }
            received = timeout(Duration::from_secs(1), phone.recv(&mut bytes)) => {
                Message::datagram(&bytes[..received??])?
            }
        };
        assert_eq!(response.status(), Some((200, "OK")));
        assert_eq!(response.cseq(), Some((1, "REGISTER")));
        let contact = format!(
            r#""Desk, East" {};maddr=127.0.0.1;expires=120"#,
            endpoint.contact
        );
        assert_eq!(response.values("Contact").collect::<Vec<_>>(), [contact]);
        Ok(())
    }

    fn test_config() -> Result<(SipConfig, Network)> {
        let cfg = SipConfig {
            auth_user: "user@ims.test".into(),
            password: "secret".into(),
            realm: "ims.test".into(),
            public_id: "sip:+910000000000@ims.test".into(),
            registrar: "ims.test".into(),
            proxy: "ims.test".into(),
        };
        let net = Network {
            local_port: 0,
            rtp_port: 0,
            bind: "127.0.0.1".parse()?,
            advertise: None,
            upstream_source: std::net::Ipv6Addr::LOCALHOST,
            destination: None,
            instance: None,
            insecure: false,
            debug_register: false,
        };
        Ok((cfg, net))
    }

    fn test_endpoint(port: u16, user: &str) -> Endpoint {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        Endpoint {
            addr,
            transport: "UDP",
            contact: format!("<sip:{user}@{addr}>"),
        }
    }

    /// Starts an outbound call from the phone and returns the INVITE sent to IMS.
    async fn start_outbound(bridge: &mut Bridge<'_>, call_id: &str) -> Result<Message> {
        let phone = test_endpoint(5060, "1000");
        let mut invite = phone.request(
            "INVITE",
            "sip:9876543210@127.0.0.1:5061",
            "<sip:1000@127.0.0.1>;tag=phone",
            "<sip:9876543210@127.0.0.1>",
            call_id,
            1,
        );
        invite.add("Contact", &phone.contact);
        invite.set_sdp("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n".into());
        let mut out = Vec::new();
        bridge
            .request(Peer::Local(phone.addr), invite, &mut out)
            .await;
        Ok(bridge
            .active
            .as_ref()
            .context("call did not start")?
            .invitation
            .request
            .clone())
    }

    #[tokio::test]
    async fn early_dialog_update_with_sdp_gets_an_answer() -> Result<()> {
        let (cfg, net) = test_config()?;
        let mut bridge = Bridge::new(
            &cfg,
            &net,
            test_endpoint(5061, "bridge"),
            test_endpoint(5062, "ims"),
            None,
        );
        let sent = &start_outbound(&mut bridge, "early-update").await?;
        let mut out = Vec::new();
        let our_tag = sip::parameter(sent.header("From").unwrap_or_default(), "tag")
            .context("INVITE has no From tag")?
            .to_owned();
        let ims = test_endpoint(5062, "ims");
        let mut update = ims.request(
            "UPDATE",
            "sip:bridge@127.0.0.1:5061",
            "<sip:+919876543210@ims.test>;tag=remote",
            &format!("<sip:+910000000000@ims.test>;tag={our_tag}"),
            sent.header("Call-ID").unwrap_or_default(),
            2,
        );
        update.set_sdp(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 7000 RTP/AVP 0\r\na=curr:qos local sendrecv\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\na=des:qos mandatory remote sendrecv\r\na=sendrecv\r\n"
                .into(),
        );
        out.clear();
        bridge.request(Peer::Upstream, update, &mut out).await;
        let reply = out
            .iter()
            .find(|delivery| delivery.peer == Peer::Upstream)
            .context("no reply to UPDATE")?;
        assert_eq!(reply.msg.status(), Some((200, "OK")));
        assert!(reply.msg.header("Contact").is_some());
        let body = String::from_utf8(reply.msg.body.clone())?;
        assert!(body.contains("o=JioCall 1 2 "), "{body}");
        assert!(body.contains("a=curr:qos local sendrecv\r\n"), "{body}");
        assert!(
            body.contains("a=des:qos mandatory local sendrecv\r\n"),
            "{body}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ringing_after_early_media_does_not_start_local_ringback() -> Result<()> {
        let (cfg, net) = test_config()?;
        let mut bridge = Bridge::new(
            &cfg,
            &net,
            test_endpoint(5061, "bridge"),
            test_endpoint(5062, "ims"),
            None,
        );
        let sent = start_outbound(&mut bridge, "early-media").await?;
        let mut progress = Message::response(&sent, 183, "Session Progress", Some("remote"));
        progress.add("Contact", "<sip:ims@127.0.0.1:5062>");
        progress.set_sdp("v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 7000 RTP/AVP 0\r\n".into());
        let mut out = Vec::new();
        bridge.response(Peer::Upstream, progress, &mut out).await;
        let to_phone = |out: &Vec<Delivery>| {
            out.iter()
                .filter(|delivery| delivery.peer != Peer::Upstream)
                .map(|delivery| delivery.msg.clone())
                .collect::<Vec<_>>()
        };
        let first = to_phone(&out);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].status(), Some((183, "Session Progress")));
        assert!(!first[0].body.is_empty());

        let mut ringing = Message::response(&sent, 180, "Ringing", Some("remote"));
        ringing.add("Contact", "<sip:ims@127.0.0.1:5062>");
        out.clear();
        bridge.response(Peer::Upstream, ringing, &mut out).await;
        for msg in to_phone(&out) {
            assert_ne!(
                msg.status().map(|(code, _)| code),
                Some(180),
                "phone got a bare 180"
            );
            assert!(!msg.body.is_empty(), "provisional to phone lost its SDP");
        }
        Ok(())
    }
}
