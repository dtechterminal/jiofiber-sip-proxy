use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

pub const TRANSACTION: Duration = Duration::from_secs(32);
pub const INVITE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_MESSAGE: usize = 64 * 1024;

pub fn id() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn branch() -> String {
    format!("z9hG4bK{}", id())
}

#[derive(Clone, Debug)]
pub struct Message {
    pub start: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Message {
    pub fn request(method: &str, uri: &str) -> Self {
        Self {
            start: format!("{method} {uri} SIP/2.0"),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn response(request: &Self, status: u16, reason: &str, tag: Option<&str>) -> Self {
        let mut msg = Self {
            start: format!("SIP/2.0 {status} {reason}"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        for via in request.values("Via") {
            msg.add("Via", via);
        }
        for name in ["From", "To", "Call-ID", "CSeq"] {
            if let Some(value) = request.header(name) {
                if name == "To"
                    && let Some(tag) = tag
                    && parameter(value, "tag").is_none()
                {
                    msg.add(name, format!("{value};tag={tag}"));
                } else {
                    msg.add(name, value);
                }
            }
        }
        if request.method() == Some("INVITE") && (101..300).contains(&status) {
            for route in request.values("Record-Route") {
                msg.add("Record-Route", route);
            }
        }
        msg
    }

    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub fn values<'a>(&'a self, name: &'a str) -> impl DoubleEndedIterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn has_option(&self, name: &str, tag: &str) -> bool {
        self.values(name)
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case(tag))
    }

    pub fn cseq(&self) -> Option<(u32, &str)> {
        let mut fields = self.header("CSeq")?.split_ascii_whitespace();
        Some((fields.next()?.parse().ok()?, fields.next()?))
    }

    pub fn method(&self) -> Option<&str> {
        (!self.start.starts_with("SIP/2.0 "))
            .then(|| self.start.split_ascii_whitespace().next())
            .flatten()
    }

    pub fn uri(&self) -> Option<&str> {
        self.method()?;
        self.start.split_ascii_whitespace().nth(1)
    }

    pub fn status(&self) -> Option<(u16, &str)> {
        let (code, reason) = self
            .start
            .strip_prefix("SIP/2.0 ")?
            .split_once(' ')
            .unwrap_or((&self.start[8..], ""));
        Some((code.parse().ok()?, reason))
    }

    pub fn set_sdp(&mut self, sdp: String) {
        self.add("Content-Type", "application/sdp");
        self.body = sdp.into_bytes();
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.start.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        for (name, value) in &self.headers {
            if !name.eq_ignore_ascii_case("Content-Length") {
                bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
        }
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn datagram(bytes: &[u8]) -> Result<Self> {
        let (mut msg, offset, len) = head(bytes)?.context("incomplete SIP datagram")?;
        let length = len.unwrap_or(bytes.len() - offset);
        ensure!(
            offset + length == bytes.len(),
            "invalid SIP datagram body length"
        );
        msg.body = bytes[offset..].to_vec();
        Ok(msg)
    }

    pub fn transaction_matches(&self, request: &Self) -> bool {
        self.header("Call-ID").is_some()
            && self.header("Call-ID") == request.header("Call-ID")
            && self.cseq().is_some()
            && self.cseq() == request.cseq()
            && self.via_branch().is_some()
            && self.via_branch() == request.via_branch()
    }

    pub fn via_branch(&self) -> Option<&str> {
        parameter(self.header("Via")?, "branch")
    }

    pub fn valid_request(&self) -> bool {
        self.method()
            .zip(self.cseq())
            .is_some_and(|(method, (_, seq_method))| method == seq_method)
            && self.header("Call-ID").is_some()
            && self.header("From").is_some()
            && self.header("To").is_some()
            && self.via_branch().is_some()
    }

    pub fn apply_rport(&mut self, peer: SocketAddr) {
        if let Some((_, via)) = self
            .headers
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case("Via"))
        {
            let (top, rest) = via.split_once(',').unwrap_or((via, ""));
            let mut fields = top.split(';');
            let sent_by = fields.next().unwrap_or_default();
            let mut adjusted = sent_by.to_owned();
            let mut requested = false;
            for field in fields {
                let name = field.split('=').next().unwrap_or_default().trim();
                if name.eq_ignore_ascii_case("rport") {
                    requested = true;
                    adjusted.push_str(&format!(";rport={}", peer.port()));
                } else if !name.eq_ignore_ascii_case("received") {
                    adjusted.push(';');
                    adjusted.push_str(field);
                }
            }
            let sent_host = sent_by
                .split_ascii_whitespace()
                .last()
                .and_then(|value| host_port(value, 5060).ok())
                .map(|(host, _)| host);
            if requested
                || sent_host.and_then(|host| host.parse::<IpAddr>().ok()) != Some(peer.ip())
            {
                adjusted.push_str(&format!(";received={}", peer.ip()));
            }
            if !rest.is_empty() {
                adjusted.push(',');
                adjusted.push_str(rest);
            }
            *via = adjusted;
        }
    }
}

fn header_name(name: &str) -> &str {
    match name.to_ascii_lowercase().as_str() {
        "v" => "Via",
        "f" => "From",
        "t" => "To",
        "i" => "Call-ID",
        "m" => "Contact",
        "l" => "Content-Length",
        "c" => "Content-Type",
        "k" => "Supported",
        _ => name,
    }
}

fn head(bytes: &[u8]) -> Result<Option<(Message, usize, Option<usize>)>> {
    let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
        ensure!(bytes.len() < MAX_MESSAGE, "SIP headers exceed size limit");
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes[..end]).context("invalid UTF-8 SIP headers")?;
    let mut lines = text.split("\r\n");
    let start = lines.next().context("empty SIP message")?;
    ensure!(
        !start.chars().any(char::is_control)
            && (start.starts_with("SIP/2.0 ") || start.ends_with(" SIP/2.0")),
        "invalid SIP start line"
    );
    let mut msg = Message {
        start: start.into(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    for line in lines {
        if line.starts_with([' ', '\t']) {
            let (_, value) = msg
                .headers
                .last_mut()
                .context("invalid folded SIP header")?;
            value.push(' ');
            value.push_str(line.trim());
        } else {
            let (key, value) = line.split_once(':').context("malformed SIP header")?;
            ensure!(
                !key.trim().is_empty() && !value.contains(['\r', '\n', '\0']),
                "malformed SIP header"
            );
            msg.add(header_name(key.trim()), value.trim());
        }
    }
    let len: Option<usize> = {
        let mut lengths = msg.values("Content-Length");
        let len = lengths
            .next()
            .map(str::parse)
            .transpose()
            .context("invalid SIP Content-Length")?;
        ensure!(lengths.next().is_none(), "duplicate SIP Content-Length");
        len
    };
    ensure!(
        len.unwrap_or(0) <= MAX_MESSAGE.saturating_sub(end + 4) && end + 4 <= MAX_MESSAGE,
        "SIP message exceeds size limit"
    );
    Ok(Some((msg, end + 4, len)))
}

pub enum Frame {
    Message(Message),
    Ping,
}

#[derive(Default)]
pub struct StreamReader {
    buffer: Vec<u8>,
}

impl StreamReader {
    pub async fn next(&mut self, reader: &mut (impl AsyncRead + Unpin)) -> Result<Frame> {
        loop {
            if self.buffer.starts_with(b"\r\n\r\n") {
                self.buffer.drain(..4);
                return Ok(Frame::Ping);
            }
            if self.buffer.starts_with(b"\r\n") && self.buffer.len() > 2 && self.buffer[2] != b'\r'
            {
                self.buffer.drain(..2);
            }
            if self.buffer.starts_with(b"\r\n")
                && self.buffer.len() >= 4
                && !self.buffer.starts_with(b"\r\n\r\n")
            {
                self.buffer.drain(..2);
            }
            if let Some((mut msg, offset, len)) = head(&self.buffer)? {
                let end = offset + len.unwrap_or(0);
                if self.buffer.len() >= end {
                    msg.body = self.buffer[offset..end].to_vec();
                    self.buffer.drain(..end);
                    return Ok(Frame::Message(msg));
                }
            }
            if reader.read_buf(&mut self.buffer).await? == 0 {
                bail!("upstream SIP connection closed");
            }
        }
    }
}

pub fn parameter<'a>(field: &'a str, key: &str) -> Option<&'a str> {
    let parameters = field.rsplit_once('>').map_or(field, |(_, suffix)| suffix);
    parameters.split(';').skip(1).find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().trim_matches('"'))
    })
}

pub fn uri_from_header(header: &str) -> Option<&str> {
    if let Some((_, tail)) = header.split_once('<') {
        return tail.split_once('>').map(|(uri, _)| uri);
    }
    header
        .trim()
        .split([' ', '\t', ','])
        .next()
        .filter(|uri| uri.starts_with("sip:") || uri.starts_with("sips:"))
}

pub fn header_list(value: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut angle = false;
    let mut start = 0;
    for (offset, ch) in value.char_indices() {
        match ch {
            '\\' if quoted && !escaped => {
                escaped = true;
                continue;
            }
            '"' if !escaped => quoted = !quoted,
            '<' if !quoted => angle = true,
            '>' if !quoted => angle = false,
            ',' if !quoted && !angle => {
                fields.push(value[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
        escaped = false;
    }
    if !value[start..].trim().is_empty() {
        fields.push(value[start..].trim());
    }
    fields
}

pub fn route_set(message: &Message, reverse: bool) -> Vec<String> {
    let mut routes: Vec<_> = message
        .values("Record-Route")
        .flat_map(header_list)
        .map(str::to_owned)
        .collect();
    if reverse {
        routes.reverse();
    }
    routes
}

pub fn host_port(value: &str, default: u16) -> Result<(&str, u16)> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .context("unterminated IPv6 address")?;
        let port = if suffix.is_empty() {
            default
        } else {
            suffix
                .strip_prefix(':')
                .context("invalid address suffix")?
                .parse()?
        };
        (host, port)
    } else if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':').context("missing host")?;
        (host, port.parse()?)
    } else {
        (value, default)
    };
    ensure!(
        !host.is_empty() && port != 0 && !host.contains([' ', '/', '@', '[', ']']),
        "invalid host or port"
    );
    Ok((host, port))
}

pub fn target_uri(number: &str, domain: &str) -> Result<String> {
    let international = number.starts_with('+');
    let number = number.strip_prefix('+').unwrap_or(number);
    ensure!(
        !number.is_empty()
            && number.len() <= 15
            && number.bytes().all(|byte| byte.is_ascii_digit()),
        "destination must be a phone number"
    );
    if international {
        Ok(format!("sip:+{number}@{domain}"))
    } else if number.len() == 10 {
        Ok(format!("sip:+91{number}@{domain}"))
    } else if number.len() == 12 && number.starts_with("91") {
        Ok(format!("sip:+{number}@{domain}"))
    } else {
        // Preserve short service numbers and already international numbers.
        Ok(format!("sip:{number}@{domain}"))
    }
}

#[derive(Clone)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub transport: &'static str,
    pub contact: String,
}

impl Endpoint {
    pub fn via(&self) -> String {
        format!(
            "SIP/2.0/{} {};branch={};rport",
            self.transport,
            self.addr,
            branch()
        )
    }

    pub fn request(
        &self,
        method: &str,
        uri: &str,
        from: &str,
        to: &str,
        call_id: &str,
        seq: u32,
    ) -> Message {
        let mut msg = Message::request(method, uri);
        msg.add("Via", self.via());
        msg.add("Max-Forwards", "70");
        msg.add("From", from);
        msg.add("To", to);
        msg.add("Call-ID", call_id);
        msg.add("CSeq", format!("{seq} {method}"));
        msg
    }
}

pub fn related_request(invite: &Message, method: &str, to: Option<&str>) -> Message {
    let mut msg = Message::request(method, invite.uri().unwrap_or_default());
    for name in ["Via", "Max-Forwards", "From", "To", "Call-ID", "Route"] {
        for value in invite.values(name) {
            msg.add(
                name,
                if name == "To" {
                    to.unwrap_or(value)
                } else {
                    value
                },
            );
        }
    }
    msg.add(
        "CSeq",
        format!("{} {method}", invite.cseq().map_or(0, |(seq, _)| seq)),
    );
    msg
}

#[derive(Clone)]
pub struct Dialog {
    pub call_id: String,
    pub from: String,
    pub to: String,
    pub target: String,
    pub routes: Vec<String>,
    pub seq: u32,
}

impl Dialog {
    pub fn outgoing(invite: &Message, response: &Message) -> Result<Self> {
        let to = response.header("To").context("INVITE response has no To")?;
        ensure!(
            parameter(to, "tag").is_some(),
            "INVITE response has no To tag"
        );
        Ok(Self {
            call_id: invite.header("Call-ID").unwrap_or_default().into(),
            from: invite.header("From").unwrap_or_default().into(),
            to: to.into(),
            target: response
                .header("Contact")
                .and_then(uri_from_header)
                .or_else(|| invite.uri())
                .unwrap_or_default()
                .into(),
            routes: route_set(response, true),
            seq: invite.cseq().map_or(0, |(seq, _)| seq),
        })
    }

    pub fn incoming(invite: &Message, local_tag: &str) -> Self {
        Self {
            call_id: invite.header("Call-ID").unwrap_or_default().into(),
            from: format!(
                "{};tag={local_tag}",
                invite.header("To").unwrap_or_default()
            ),
            to: invite.header("From").unwrap_or_default().into(),
            target: invite
                .header("Contact")
                .and_then(uri_from_header)
                .or_else(|| invite.header("From").and_then(uri_from_header))
                .unwrap_or_default()
                .into(),
            routes: route_set(invite, false),
            seq: 0,
        }
    }

    pub fn matches(&self, msg: &Message) -> bool {
        let remote_tag = parameter(&self.to, "tag");
        let local_tag = parameter(&self.from, "tag");
        !self.call_id.is_empty()
            && msg.header("Call-ID") == Some(self.call_id.as_str())
            && remote_tag.is_some()
            && msg.header("From").and_then(|value| parameter(value, "tag")) == remote_tag
            && local_tag.is_some()
            && msg.header("To").and_then(|value| parameter(value, "tag")) == local_tag
    }

    pub fn request(&self, endpoint: &Endpoint, method: &str, seq: u32) -> Message {
        let mut routes = self.routes.clone();
        let mut uri = self.target.as_str();
        if let Some(first) = self.routes.first().and_then(|route| uri_from_header(route))
            && !first.split(';').skip(1).any(|param| {
                param
                    .split('=')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("lr"))
            })
        {
            uri = first;
            routes.remove(0);
            routes.push(format!("<{}>", self.target));
        }
        let mut msg = endpoint.request(method, uri, &self.from, &self.to, &self.call_id, seq);
        for route in routes {
            msg.add("Route", route);
        }
        msg
    }

    pub fn next_request(&mut self, endpoint: &Endpoint, method: &str) -> Message {
        self.seq += 1;
        self.request(endpoint, method, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn tls_framing_handles_ping_and_multiple_messages() -> Result<()> {
        let (mut writer, mut reader) = duplex(1024);
        let mut sip = StreamReader::default();
        writer.write_all(b"\r\n").await?;
        let first = b"OPTIONS sip:bridge@example.test SIP/2.0\r\ni: first\r\nl: 2\r\n\r\n\xc3\xa9";
        let split = first.len() - 1;
        writer.write_all(b"\r\n").await?;
        writer.write_all(&first[..split]).await?;
        assert!(matches!(sip.next(&mut reader).await?, Frame::Ping));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), sip.next(&mut reader))
                .await
                .is_err()
        );
        writer.write_all(&first[split..]).await?;
        writer
            .write_all(b"SIP/2.0 200 OK\r\nCall-ID: second\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let Frame::Message(first) = sip.next(&mut reader).await? else {
            panic!("missing first message")
        };
        let Frame::Message(second) = sip.next(&mut reader).await? else {
            panic!("missing second message")
        };
        assert_eq!(first.body, b"\xc3\xa9");
        assert_eq!(first.header("Call-ID"), Some("first"));
        assert_eq!(second.header("Call-ID"), Some("second"));
        Ok(())
    }
}
