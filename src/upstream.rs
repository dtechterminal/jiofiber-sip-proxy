use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use hickory_resolver::{
    TokioAsyncResolver,
    proto::rr::{RData, RecordType},
};
use native_tls::Protocol;
use tokio::{
    io::{AsyncWriteExt, ReadHalf, WriteHalf, split},
    net::{TcpSocket, TcpStream},
    time::{Instant, timeout},
};
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::{
    config::{Network, SipConfig, USER_AGENT},
    digest,
    sip::{self, Endpoint, Frame, Message, StreamReader},
};

pub const ALLOW: &str = "INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, OPTIONS";
const EXPIRY: u64 = 600_000;

type Tls = TlsStream<TcpStream>;

/// Resolves the P-CSCF using the 3GPP DNS procedure (TS 24.229): NAPTR to find the
/// SIP transport service, SRV to find the host and port, then A/AAAA. Provisioned
/// IMS profiles give the home domain (e.g. `ue.wln.ims.jio.com`), which carries only
/// NAPTR/SRV records and no address of its own, so a plain lookup fails. An IP literal
/// or an already-resolved host (e.g. `pcscf.ue.wln.ims.jio.com`) falls through to a
/// direct address lookup. Returns the TLS server name alongside the addresses.
async fn resolve_proxy(host: &str, default_port: u16) -> Result<(String, Vec<SocketAddr>)> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((host.to_owned(), vec![SocketAddr::new(ip, default_port)]));
    }
    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().context("initialising DNS resolver")?;

    // Prefer SRV targets named by NAPTR; otherwise try the conventional SIP SRV names.
    let mut srv_names: Vec<String> = Vec::new();
    if let Ok(naptr) = resolver.lookup(host, RecordType::NAPTR).await {
        let mut records: Vec<_> = naptr
            .iter()
            .filter_map(|data| match data {
                RData::NAPTR(record) => Some(record),
                _ => None,
            })
            .collect();
        records.sort_by_key(|record| (record.order(), record.preference()));
        for record in records {
            // Secure (SIPS) first so the TLS leg is preferred, matching the proxy's transport.
            if matches!(record.services(), b"SIPS+D2T" | b"SIP+D2T" | b"SIP+D2U") {
                srv_names.push(record.replacement().to_utf8());
            }
        }
    }
    if srv_names.is_empty() {
        srv_names.push(format!("_sips._tcp.{host}"));
        srv_names.push(format!("_sip._tcp.{host}"));
    }

    for srv_name in &srv_names {
        let Ok(srv) = resolver.srv_lookup(srv_name.trim_end_matches('.')).await else {
            continue;
        };
        let Some(record) = srv
            .iter()
            .min_by_key(|record| (record.priority(), u16::MAX - record.weight()))
        else {
            continue;
        };
        let target = record.target().to_utf8().trim_end_matches('.').to_owned();
        let port = record.port();
        if let Ok(ips) = resolver.lookup_ip(target.as_str()).await {
            let addresses: Vec<_> = ips.iter().map(|ip| SocketAddr::new(ip, port)).collect();
            if !addresses.is_empty() {
                return Ok((target, addresses));
            }
        }
    }

    // Fallback: the host already has address records of its own.
    let ips = resolver
        .lookup_ip(host)
        .await
        .with_context(|| format!("resolving SIP proxy {host}"))?;
    let addresses: Vec<_> = ips
        .iter()
        .map(|ip| SocketAddr::new(ip, default_port))
        .collect();
    ensure!(!addresses.is_empty(), "SIP proxy {host} has no address");
    Ok((host.to_owned(), addresses))
}

fn contact_uri(auth_user: &str, addr: SocketAddr) -> String {
    let user = auth_user
        .split_once('@')
        .map_or(auth_user, |(user, _)| user);
    format!("sip:{user}@{addr};transport=tls")
}

pub struct Upstream {
    pub endpoint: Endpoint,
    reader: ReadHalf<Tls>,
    writer: WriteHalf<Tls>,
    framing: StreamReader,
    debug_register: bool,
}

impl Upstream {
    pub async fn connect(cfg: &SipConfig, net: &Network, instance: &str) -> Result<Self> {
        // When registering through the ONT, the upstream is a LAN IPv4 TLS leg to
        // `<router>:5068` with a self-signed certificate; otherwise it is the IPv6 P-CSCF.
        let (host, port) = sip::host_port(&cfg.proxy, 5061).context("invalid PROXY_HOST")?;
        let (server_name, addresses) = timeout(Duration::from_secs(8), resolve_proxy(host, port))
            .await
            .context("SIP proxy lookup timed out")??;
        // The P-CSCF needs TLS_RSA_WITH_AES_128_CBC_SHA256, available through OpenSSL on Linux.
        let connector = TlsConnector::from(
            native_tls::TlsConnector::builder()
                .min_protocol_version(Some(Protocol::Tlsv12))
                .danger_accept_invalid_certs(net.insecure)
                .danger_accept_invalid_hostnames(net.insecure)
                .build()
                .context("configuring upstream SIP TLS")?,
        );
        let src = SocketAddr::new(IpAddr::V6(net.upstream_source), net.local_port);
        let mut errors = None;
        for remote in addresses.into_iter().filter(SocketAddr::is_ipv6) {
            let result = timeout(Duration::from_secs(10), async {
                let socket = TcpSocket::new_v6()?;
                socket.set_reuseaddr(true)?;
                socket.bind(src).context("binding upstream SIP socket")?;
                let tcp = socket
                    .connect(remote)
                    .await
                    .context("connecting upstream SIP socket")?;
                tcp.set_nodelay(true)?;
                let local = tcp.local_addr()?;
                let tls = connector
                    .connect(&server_name, tcp)
                    .await
                    .context("upstream SIP TLS handshake")?;
                Ok::<_, anyhow::Error>((local, tls))
            })
            .await
            .context("upstream SIP connect timeout")
            .and_then(|result| result);
            match result {
                Ok((addr, tls)) => {
                    let (reader, writer) = split(tls);
                    let uri = contact_uri(&cfg.auth_user, addr);
                    let contact = format!(
                        "<{uri}>;+sip.instance=\"{instance}\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
                    );
                    return Ok(Self {
                        endpoint: Endpoint {
                            addr,
                            transport: "TLS",
                            contact,
                        },
                        reader,
                        writer,
                        framing: StreamReader::default(),
                        debug_register: net.debug_register,
                    });
                }
                Err(error) => errors = Some(error),
            }
        }
        Err(errors.unwrap_or_else(|| anyhow::anyhow!("SIP proxy has no IPv6 address")))
    }

    pub async fn recv(&mut self) -> Result<Frame> {
        self.framing.next(&mut self.reader).await
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let bytes = msg.encode();
        if self.debug_register && msg.method() == Some("REGISTER") {
            eprint!("{}", String::from_utf8_lossy(&bytes));
        }
        self.write(&bytes).await
    }

    pub async fn pong(&mut self) -> Result<()> {
        self.write(b"\r\n").await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        timeout(Duration::from_secs(5), self.writer.write_all(bytes))
            .await
            .context("upstream SIP write timeout")?
            .context("writing upstream SIP")
    }
}

pub fn auth(
    cfg: &SipConfig,
    response: &Message,
    status: u16,
    method: &str,
    uri: &str,
) -> Result<(&'static str, String)> {
    let (source, target) = if status == 407 {
        ("Proxy-Authenticate", "Proxy-Authorization")
    } else {
        ("WWW-Authenticate", "Authorization")
    };
    let challenge = response
        .values(source)
        .find(|value| {
            value
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Digest "))
        })
        .context("SIP response has no Digest challenge")?;
    Ok((
        target,
        digest::response(challenge, &cfg.auth_user, &cfg.password, method, uri)?,
    ))
}

pub struct Registration {
    call_id: String,
    from: String,
    seq: u32,
    pending: Option<(Message, Instant)>,
    refresh: Instant,
    expiry: u64,
    retries: u8,
}

impl Registration {
    pub fn new(cfg: &SipConfig) -> Self {
        Self {
            call_id: sip::id(),
            from: format!("<{}>;tag={}", cfg.public_id, sip::id()),
            seq: 0,
            pending: None,
            refresh: Instant::now(),
            expiry: EXPIRY,
            retries: 0,
        }
    }

    fn uri(cfg: &SipConfig) -> String {
        format!("sip:{}", cfg.realm)
    }

    fn request(
        &mut self,
        cfg: &SipConfig,
        endpoint: &Endpoint,
        name: &str,
        authorization: String,
    ) -> Message {
        self.seq += 1;
        let mut msg = endpoint.request(
            "REGISTER",
            &Self::uri(cfg),
            &self.from,
            &format!("<{}>", cfg.public_id),
            &self.call_id,
            self.seq,
        );
        msg.add(
            "Contact",
            format!("<{}>", contact_uri(&cfg.auth_user, endpoint.addr)),
        );
        msg.add(name, authorization);
        msg.add("Expires", self.expiry.to_string());
        msg.add("P-Access-Network-Info", "GPON");
        msg.add("Supported", "path,outbound,gruu");
        msg.add("User-Agent", USER_AGENT);
        self.pending = Some((msg.clone(), Instant::now() + Duration::from_secs(10)));
        msg
    }

    fn probe(&mut self, cfg: &SipConfig, endpoint: &Endpoint) -> Message {
        let auth =
            digest::registration_probe(&cfg.auth_user, &cfg.password, &cfg.realm, &Self::uri(cfg));
        self.request(cfg, endpoint, "Authorization", auth)
    }

    pub fn tick(
        &mut self,
        cfg: &SipConfig,
        endpoint: &Endpoint,
        now: Instant,
    ) -> Result<Option<Message>> {
        if let Some((_, deadline)) = &self.pending {
            ensure!(now < *deadline, "upstream REGISTER timed out");
        } else if now >= self.refresh {
            self.retries = 0;
            return Ok(Some(self.probe(cfg, endpoint)));
        }
        Ok(None)
    }

    pub fn handle(
        &mut self,
        cfg: &SipConfig,
        endpoint: &Endpoint,
        response: &Message,
    ) -> Result<Option<Message>> {
        let Some((request, _)) = &self.pending else {
            return Ok(None);
        };
        if !response.transaction_matches(request) {
            return Ok(None);
        }
        let Some((status, _)) = response.status() else {
            return Ok(None);
        };
        match status {
            100..=199 => Ok(None),
            200..=299 => {
                let own_contact = request.header("Contact").and_then(sip::uri_from_header);
                let expiry = response
                    .values("Contact")
                    .flat_map(|field| field.split(','))
                    .find(|value| sip::uri_from_header(value) == own_contact)
                    .and_then(|value| sip::parameter(value, "expires"))
                    .or_else(|| response.header("Expires"))
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(self.expiry);
                ensure!(expiry > 0, "upstream registration was removed");
                self.refresh =
                    Instant::now() + Duration::from_secs((expiry.min(EXPIRY) * 4 / 5).max(1));
                self.pending = None;
                Ok(None)
            }
            401 | 407 if self.retries < 2 => {
                self.retries += 1;
                let (header, auth) = auth(cfg, response, status, "REGISTER", &Self::uri(cfg))?;
                Ok(Some(self.request(cfg, endpoint, header, auth)))
            }
            423 if self.retries < 2 => {
                let min = response
                    .header("Min-Expires")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|min| *min > self.expiry)
                    .context("invalid Min-Expires on REGISTER")?;
                self.expiry = min;
                self.retries += 1;
                Ok(Some(self.probe(cfg, endpoint)))
            }
            _ => bail!("upstream REGISTER failed with SIP {status}"),
        }
    }

    pub async fn initial(&mut self, cfg: &SipConfig, upstream: &mut Upstream) -> Result<()> {
        let request = self.probe(cfg, &upstream.endpoint);
        upstream.send(&request).await?;
        while let Some((_, deadline)) = &self.pending {
            match tokio::time::timeout_at(*deadline, upstream.recv())
                .await
                .context("upstream REGISTER timed out")??
            {
                Frame::Ping => upstream.pong().await?,
                Frame::Message(msg) if msg.method().is_some() && msg.valid_request() => {
                    let tag = sip::id();
                    let (status, reason) = if msg.method() == Some("OPTIONS") {
                        (200, "OK")
                    } else {
                        (503, "Service Unavailable")
                    };
                    if msg.method() != Some("ACK") {
                        upstream
                            .send(&Message::response(&msg, status, reason, Some(&tag)))
                            .await?;
                    }
                }
                Frame::Message(msg) => {
                    if let Some(request) = self.handle(cfg, &upstream.endpoint, &msg)? {
                        upstream.send(&request).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_matches_the_ims_wire_format() -> Result<()> {
        let cfg = SipConfig {
            auth_user: "910000000000@ims.example.test".into(),
            password: "fixture-password".into(),
            realm: "ims.example.test".into(),
            public_id: "sip:+910000000000@ims.example.test".into(),
            registrar: "registrar.example.test".into(),
            proxy: "pcscf.example.test".into(),
        };
        let endpoint = Endpoint {
            addr: "[2001:db8::1]:45678".parse()?,
            transport: "TLS",
            contact: "<sip:910000000000@[2001:db8::1]:45678;transport=tls>;+sip.instance=\"test\""
                .into(),
        };
        let mut registration = Registration::new(&cfg);
        let probe = registration.probe(&cfg, &endpoint);
        let tag = sip::parameter(&registration.from, "tag").context("REGISTER From tag")?;
        let branch = probe.via_branch().context("REGISTER Via branch")?;
        assert!(branch.starts_with("z9hG4bK"));
        let expected = format!(
            concat!(
                "REGISTER sip:ims.example.test SIP/2.0\r\n",
                "Via: SIP/2.0/TLS [2001:db8::1]:45678;branch={branch};rport\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:+910000000000@ims.example.test>;tag={tag}\r\n",
                "To: <sip:+910000000000@ims.example.test>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 REGISTER\r\n",
                "Contact: <sip:910000000000@[2001:db8::1]:45678;transport=tls>\r\n",
                "Authorization: Digest username=\"910000000000@ims.example.test\", realm=\"ims.example.test\", ",
                "nonce=\"\", uri=\"sip:ims.example.test\", response=\"ffa982ba7b87e873fcdc0311085876f0\", algorithm=MD5\r\n",
                "Expires: 600000\r\n",
                "P-Access-Network-Info: GPON\r\n",
                "Supported: path,outbound,gruu\r\n",
                "User-Agent: JCOW414/JUICEJFV-1.3.31\r\n",
                "Content-Length: 0\r\n\r\n",
            ),
            branch = branch,
            tag = tag,
            call_id = registration.call_id,
        );
        assert_eq!(probe.encode(), expected.as_bytes());

        let mut challenge = Message::response(&probe, 401, "Unauthorized", Some("registrar"));
        challenge.add(
            "WWW-Authenticate",
            r#"Digest realm="ims.example.test", nonce="fixture-nonce", qop="auth""#,
        );
        let retry = registration
            .handle(&cfg, &endpoint, &challenge)?
            .context("missing authenticated REGISTER")?;
        assert_eq!(retry.uri(), probe.uri());
        assert_eq!(retry.header("Contact"), probe.header("Contact"));
        assert_eq!(retry.header("Call-ID"), probe.header("Call-ID"));
        assert_eq!(retry.cseq(), Some((2, "REGISTER")));
        let auth = retry
            .header("Authorization")
            .context("missing Digest authorization")?;
        let (_, proof) = auth
            .strip_prefix(concat!(
                r#"Digest username="910000000000@ims.example.test", realm="ims.example.test", "#,
                r#"nonce="fixture-nonce", uri="sip:ims.example.test", qop=auth, nc=00000001, cnonce=""#,
            ))
            .and_then(|value| value.split_once(r#"", response=""#))
            .context("unexpected REGISTER Digest format")?;
        assert_eq!(
            proof.strip_suffix(r#"", algorithm=MD5"#).map(str::len),
            Some(32)
        );
        Ok(())
    }
}
