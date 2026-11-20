//! Hand the line to this proxy by turning off the JioFiber ONT's own SIP.
//!
//! IMS allows one registration per identity, so if the ONT keeps registering the line it
//! will fight this proxy for the binding. When `ONT_HOST` is configured, at startup the
//! proxy telnets into the ONT (trying the known default logins, or an explicit
//! `ONT_TELNET_USER`/`ONT_TELNET_PASSWORD`) and disables its voice stack two ways:
//!
//! * **Persistently** — the rootfs is a read-only squashfs, but `platformInit3` runs a
//!   writable override `/flash2/pfrm2.0/etc/voipInit` *instead of* the stock one when it
//!   exists. We install an override there that sets up the voip status files but never
//!   launches `hgw-voice-app`. Reversible: delete that file to restore stock voice.
//! * **Immediately** — `killall hgw-voice-app` drops any current registration without a reboot.
//!
//! This writes to the ONT, so it only runs when explicitly configured (`ONT_HOST` set).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

use crate::config;

/// The persistent `voipInit` override we install on the ONT's writable `/flash2`.
/// `\n` are kept as two characters so the ONT's `printf` expands them into real newlines.
const OVERRIDE_PRINTF: &str = "#!/bin/sh\\n\
# jiofiber-sip-proxy: ONT voice disabled so the proxy owns the IMS registration.\\n\
# Delete this file to restore the stock voice stack.\\n\
touch /tmp/voipRegStatus /tmp/voipOutgoingTo /tmp/voipIncomingFrom /tmp/voipCallStatus\\n\
echo NO > /tmp/voipRegStatus\\n\
echo N/A > /tmp/voipOutgoingTo\\n\
echo N/A > /tmp/voipIncomingFrom\\n\
echo N/A > /tmp/voipCallStatus\\n";

const OVERRIDE_PATH: &str = "/flash2/pfrm2.0/etc/voipInit";
const MARKER: &str = "jiofiber-sip-proxy";

/// Published default telnet login for JioFiber ONTs, tried when no explicit
/// `ONT_TELNET_PASSWORD` is given. This is the well-known factory `root` login (documented in
/// the JioFiber community), not a per-device secret — an explicit user/password overrides it.
/// (The web-UI `superadmin` account is what *enables* telnet/root; it is not a telnet login.)
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[("root", "123G@mers")];

/// Telnet target for the ONT.
pub struct Ont {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

impl Ont {
    /// The ordered list of telnet logins to try for `ONT_HOST`, or `None` when it is unset
    /// (feature off). With an explicit `ONT_TELNET_PASSWORD` we try only that login; otherwise
    /// we try the known JioFiber defaults in order, so the common case needs no password.
    pub fn candidates_from_env() -> Result<Option<Vec<Self>>> {
        let Some(host) = config::optional("ONT_HOST") else {
            return Ok(None);
        };
        let port = config::parsed("ONT_TELNET_PORT")?.unwrap_or(23);
        Ok(Some(Self::candidates(
            host,
            port,
            config::optional("ONT_TELNET_USER"),
            config::optional("ONT_TELNET_PASSWORD"),
        )))
    }

    /// Build the logins to try. An explicit password yields exactly one; without a password we
    /// try the built-in defaults (pinned to `user` if one was given, else all of them).
    pub fn candidates(
        host: String,
        port: u16,
        user: Option<String>,
        password: Option<String>,
    ) -> Vec<Self> {
        if let Some(password) = password {
            let user = user.unwrap_or_else(|| DEFAULT_CREDENTIALS[0].0.to_owned());
            return vec![Self {
                host,
                port,
                user,
                password,
            }];
        }
        let mut out: Vec<Self> = DEFAULT_CREDENTIALS
            .iter()
            .filter(|(u, _)| {
                user.as_deref()
                    .is_none_or(|want| want.eq_ignore_ascii_case(u))
            })
            .map(|(u, p)| Self {
                host: host.clone(),
                port,
                user: (*u).to_owned(),
                password: (*p).to_owned(),
            })
            .collect();
        // A custom user with no password: try it against the known default passwords.
        if out.is_empty()
            && let Some(user) = user
        {
            out = DEFAULT_CREDENTIALS
                .iter()
                .map(|(_, p)| Self {
                    host: host.clone(),
                    port,
                    user: user.clone(),
                    password: (*p).to_owned(),
                })
                .collect();
        }
        out
    }
}

/// The commands that disable voice, run in order over the telnet session. Installing the
/// override is idempotent (skipped when our marker is already present).
fn disable_commands() -> [String; 3] {
    [
        format!(
            "grep -q {MARKER} {OVERRIDE_PATH} 2>/dev/null || {{ mkdir -p /flash2/pfrm2.0/etc && \
             printf '{OVERRIDE_PRINTF}' > {OVERRIDE_PATH} && chmod +x {OVERRIDE_PATH} && \
             echo INSTALLED_OVERRIDE; }}"
        ),
        "killall hgw-voice-app 2>/dev/null; echo KILL_DONE".to_owned(),
        format!("grep -q {MARKER} {OVERRIDE_PATH} 2>/dev/null && echo OVERRIDE_PRESENT"),
    ]
}

/// Telnet in and disable the ONT's voice stack. Returns a short status string. Tries each
/// login in `candidates` until one works (see [`Ont::candidates`]).
pub async fn disable_voice(candidates: &[Ont]) -> Result<String> {
    let (mut session, _user) = Session::login_first(candidates).await?;
    let mut transcript = String::new();
    for command in disable_commands() {
        transcript.push_str(&session.run(&command).await?);
    }
    let _ = session.stream.write_all(b"exit\r\n").await;
    Ok(summarize(&transcript))
}

fn summarize(transcript: &str) -> String {
    let persistent = transcript.contains("OVERRIDE_PRESENT");
    let installed = transcript.contains("INSTALLED_OVERRIDE");
    let killed = transcript.contains("KILL_DONE");
    let state = if installed {
        "override installed"
    } else if persistent {
        "override already present"
    } else {
        "override NOT confirmed"
    };
    format!(
        "{state}; voice app {}",
        if killed {
            "killed"
        } else {
            "kill not confirmed"
        }
    )
}

/// What the Jio ONT can tell us about itself over telnet, so the user need not type it.
///
/// Only Jio-specific, topology-independent facts live here: the serial and the TR-069
/// password sit on the ONT even when it is bridged/AP (verified on a bridged unit). The
/// line's source `/64` is **not** read here — in AP/bridge mode the ONT's own address can
/// differ from the `/64` the proxy host sources from, so that comes from the host instead.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Discovery {
    /// Device serial, from the `<serial>_<model>.enc` settings-backup filename on `/flash`.
    pub serial: Option<String>,
    pub model: Option<String>,
    /// The TR-069/ACS password, read straight from `/tmp/acs_passwd`.
    pub tr069_password: Option<String>,
    /// The telnet user that successfully logged in (e.g. which default credential worked).
    pub auth_user: Option<String>,
}

/// Telnet in (read-only) and read whatever identity the ONT exposes, so provisioning needs
/// no hand-entered serial or TR-069 password. Missing pieces come back as `None`, and the
/// caller falls back to the environment. This is best-effort: a non-Jio device simply yields
/// an empty `Discovery`.
pub async fn discover(candidates: &[Ont]) -> Result<Discovery> {
    let (mut session, auth_user) = Session::login_first(candidates).await?;
    let enc = session
        .read_field("ls -1 /flash/ 2>/dev/null | grep -i '[.]enc$' | head -n1")
        .await;
    let (serial, model) = enc.as_deref().map(split_enc).unwrap_or((None, None));
    let tr069_password = session.read_field("cat /tmp/acs_passwd 2>/dev/null").await;
    let _ = session.stream.write_all(b"exit\r\n").await;
    Ok(Discovery {
        serial,
        model,
        tr069_password,
        auth_user: Some(auth_user),
    })
}

/// Split a `<serial>_<model>.enc` backup filename into its serial and model.
fn split_enc(name: &str) -> (Option<String>, Option<String>) {
    let stem = name.trim();
    let stem = stem
        .strip_suffix(".enc")
        .or_else(|| stem.strip_suffix(".ENC"))
        .unwrap_or(stem);
    match stem.split_once('_') {
        Some((s, m)) if !s.is_empty() && !m.is_empty() => (Some(s.to_owned()), Some(m.to_owned())),
        _ => (None, None),
    }
}

/// A LAN-scan hit: an address that answered telnet and verified as a Jio ONT.
pub struct ScanHit {
    pub host: String,
    pub discovery: Discovery,
}

/// Scan the local network for a reachable Jio ONT, so the user need not know its address.
/// Probes well-known default addresses plus every host on the directly-connected IPv4 subnets
/// for an open telnet port, then logs into each candidate with the default login and keeps the
/// first that looks like an ONT (yields a serial or TR-069 password). Subnet discovery is
/// Linux-only (`/proc/net/route`); elsewhere only the known defaults are probed.
pub async fn scan() -> Result<Option<ScanHit>> {
    let mut candidates = scan_candidates();
    candidates.sort();
    candidates.dedup();
    let open = probe_open(&candidates, 23, Duration::from_millis(400)).await;
    for ip in open {
        let host = ip.to_string();
        let targets = Ont::candidates(host.clone(), 23, None, None);
        if let Ok(found) = discover(&targets).await
            && (found.serial.is_some() || found.tr069_password.is_some())
        {
            return Ok(Some(ScanHit {
                host,
                discovery: found,
            }));
        }
    }
    Ok(None)
}

/// Addresses to probe: well-known JioFiber ONT defaults plus the hosts of each directly
/// connected IPv4 `/24`–`/30` from the routing table.
fn scan_candidates() -> Vec<Ipv4Addr> {
    const KNOWN: &[[u8; 4]] = &[
        [192, 168, 0, 51],
        [192, 168, 29, 1],
        [192, 168, 1, 1],
        [192, 168, 0, 1],
    ];
    let mut out: Vec<Ipv4Addr> = KNOWN.iter().map(|octets| Ipv4Addr::from(*octets)).collect();
    for (network, prefix) in connected_networks() {
        if !(24..=30).contains(&prefix) {
            continue; // keep the sweep bounded
        }
        let base = u32::from(network);
        let count = 1u32 << (32 - prefix);
        for offset in 1..count.saturating_sub(1) {
            out.push(Ipv4Addr::from(base + offset)); // skip network and broadcast
        }
    }
    out.truncate(2048);
    out
}

/// Directly-connected IPv4 networks `(network, prefix_len)` from Linux `/proc/net/route`.
/// The hex fields are stored little-endian, so each is byte-swapped back to host order.
fn connected_networks() -> Vec<(Ipv4Addr, u8)> {
    let Ok(data) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut nets = Vec::new();
    for line in data.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let (Ok(dest), Ok(gateway), Ok(mask)) = (
            u32::from_str_radix(cols[1], 16),
            u32::from_str_radix(cols[2], 16),
            u32::from_str_radix(cols[7], 16),
        ) else {
            continue;
        };
        if gateway != 0 || mask == 0 {
            continue; // only directly-connected subnets (no gateway)
        }
        nets.push((
            Ipv4Addr::from(dest.swap_bytes()),
            mask.swap_bytes().count_ones() as u8,
        ));
    }
    nets
}

/// Probe each address's TCP `port`, returning those that accept a connection within `budget`.
async fn probe_open(addresses: &[Ipv4Addr], port: u16, budget: Duration) -> Vec<Ipv4Addr> {
    let mut open = Vec::new();
    for chunk in addresses.chunks(128) {
        let mut set = tokio::task::JoinSet::new();
        for &ip in chunk {
            set.spawn(async move {
                let reachable = timeout(budget, TcpStream::connect(SocketAddr::from((ip, port))))
                    .await
                    .is_ok_and(|result| result.is_ok());
                (ip, reachable)
            });
        }
        while let Some(Ok((ip, reachable))) = set.join_next().await {
            if reachable {
                open.push(ip);
            }
        }
    }
    open.sort();
    open
}

/// A minimal telnet session: enough IAC handling to log in and run commands on BusyBox.
struct Session {
    stream: TcpStream,
    seq: u32,
}

impl Session {
    /// Try each candidate login in order; return the first session that reaches a shell, along
    /// with the user that worked. Reports the last failure if none succeed.
    async fn login_first(candidates: &[Ont]) -> Result<(Self, String)> {
        let mut last = None;
        for ont in candidates {
            match Self::login(ont).await {
                Ok(session) => return Ok((session, ont.user.clone())),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no telnet credentials to try for the ONT")))
    }

    async fn login(ont: &Ont) -> Result<Self> {
        let stream = timeout(
            Duration::from_secs(8),
            TcpStream::connect((ont.host.as_str(), ont.port)),
        )
        .await
        .context("connecting to the ONT telnet port")?
        .context("connecting to the ONT telnet port")?;
        let mut session = Self { stream, seq: 0 };
        session
            .read_until("login:", Duration::from_secs(8))
            .await
            .context("waiting for the ONT login prompt")?;
        session.send(&ont.user).await?;
        session
            .read_until("assword:", Duration::from_secs(8))
            .await
            .context("waiting for the ONT password prompt")?;
        session.send(&ont.password).await?;
        // Confirm we actually got a shell (a wrong password loops back to `login:`).
        let probe = session.run("id").await?;
        ensure!(
            probe.contains("uid="),
            "ONT telnet login failed (check ONT_TELNET_USER / ONT_TELNET_PASSWORD)"
        );
        Ok(session)
    }

    async fn send(&mut self, line: &str) -> Result<()> {
        self.stream.write_all(line.as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Run a command and return its output. A sentinel marks completion; the `""` keeps the
    /// marker out of the device's command echo so we match only the real output line.
    async fn run(&mut self, command: &str) -> Result<String> {
        self.seq += 1;
        let marker = format!("x7q9done{}", self.seq);
        let echoed = format!("x7q9\"\"done{}", self.seq);
        self.send(&format!("{command}; echo {echoed}")).await?;
        let out = self
            .read_until(&marker, Duration::from_secs(12))
            .await
            .with_context(|| format!("running `{command}` on the ONT"))?;
        Ok(out)
    }

    /// Run a command and return the trimmed value it prints, captured between split sentinels
    /// so the device's command echo can never be mistaken for the output. Returns `None` for
    /// an empty result or any failure (the field is simply treated as undiscovered).
    async fn read_field(&mut self, command: &str) -> Option<String> {
        self.seq += 1;
        let n = self.seq;
        let open = format!("JF{n}A");
        let close = format!("JF{n}B");
        // `''` concatenates to nothing in the shell: the format string becomes JF{n}A%sJF{n}B,
        // so the printed output holds the whole sentinel while the echoed command never does.
        let wrapped = format!("printf 'JF{n}''A%sJF{n}''B' \"$({command})\"");
        self.send(&wrapped).await.ok()?;
        let out = self
            .read_until(&close, Duration::from_secs(10))
            .await
            .ok()?;
        let start = out.find(&open)? + open.len();
        let tail = &out[start..];
        let end = tail.find(&close)?;
        let value = tail[..end].trim();
        (!value.is_empty()).then(|| value.to_owned())
    }

    /// Read, handling telnet IAC negotiation, until `needle` appears or time runs out.
    async fn read_until(&mut self, needle: &str, budget: Duration) -> Result<String> {
        let deadline = Instant::now() + budget;
        let mut acc = String::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .with_context(|| format!("timed out waiting for `{needle}` from the ONT"))?;
            let chunk = timeout(remaining, self.pump())
                .await
                .with_context(|| format!("timed out waiting for `{needle}` from the ONT"))??;
            match chunk {
                // Real end-of-stream — the server hung up.
                None => bail!("ONT closed the telnet connection while waiting for `{needle}`"),
                // A chunk that was pure IAC negotiation yields no text; that is not EOF, so
                // keep reading (the login prompt arrives only after we answer negotiation).
                Some(text) => {
                    acc.push_str(&text);
                    if acc.contains(needle) {
                        return Ok(acc);
                    }
                }
            }
        }
    }

    /// Read one chunk, answering IAC DO/WILL with WONT/DONT and returning the plain text.
    /// `Ok(None)` means EOF (the socket is closed); `Ok(Some(""))` is a chunk that was all
    /// telnet negotiation and carried no displayable text.
    async fn pump(&mut self) -> Result<Option<String>> {
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        let (text, response) = strip_iac(&buf[..n]);
        if !response.is_empty() {
            self.stream.write_all(&response).await?;
        }
        Ok(Some(String::from_utf8_lossy(&text).into_owned()))
    }
}

/// Split a telnet byte stream into displayable text and the IAC response to send back
/// (refuse every option: WILL→DONT, DO→WONT).
fn strip_iac(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mut text, mut response) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 255 {
            match data.get(i + 1) {
                Some(255) => {
                    text.push(255); // escaped literal 0xFF
                    i += 2;
                }
                Some(&cmd @ (251 | 253)) if i + 2 < data.len() => {
                    let opt = data[i + 2];
                    let reply = if cmd == 251 { 254 } else { 252 };
                    response.extend_from_slice(&[255, reply, opt]);
                    i += 3;
                }
                Some(_) => i += 2, // other 2-byte IAC command
                None => i += 1,
            }
        } else {
            text.push(data[i]);
            i += 1;
        }
    }
    (text, response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_iac_refuses_options_and_keeps_text() {
        // IAC DO ECHO (255,253,1), "hi", IAC WILL SGA (255,251,3)
        let data = [255, 253, 1, b'h', b'i', 255, 251, 3];
        let (text, response) = strip_iac(&data);
        assert_eq!(text, b"hi");
        // DO->WONT (252), WILL->DONT (254)
        assert_eq!(response, vec![255, 252, 1, 255, 254, 3]);
    }

    #[test]
    fn override_disables_without_launching_voice() {
        // The installed override must set status files but never start the voice app.
        assert!(OVERRIDE_PRINTF.contains("voipRegStatus"));
        assert!(!OVERRIDE_PRINTF.contains("hgw-voice-app"));
        assert!(OVERRIDE_PRINTF.contains(MARKER));
    }

    #[test]
    fn split_enc_parses_serial_and_model() {
        assert_eq!(
            split_enc("RSVEXAMPLE000000_JCOW414.enc"),
            (Some("RSVEXAMPLE000000".into()), Some("JCOW414".into()))
        );
        // no underscore / not a backup name → nothing usable
        assert_eq!(split_enc("backup.enc"), (None, None));
        assert_eq!(split_enc(""), (None, None));
    }

    #[test]
    fn disable_commands_are_idempotent_and_kill() {
        let cmds = disable_commands();
        assert!(cmds[0].contains(&format!("grep -q {MARKER}")));
        assert!(cmds[0].contains("printf"));
        assert!(cmds[1].contains("killall hgw-voice-app"));
    }

    #[test]
    fn candidates_without_password_try_the_defaults() {
        let list = Ont::candidates("10.0.0.1".into(), 23, None, None);
        assert_eq!(list.len(), DEFAULT_CREDENTIALS.len());
        assert_eq!(list[0].user, "root");
        assert!(list.iter().all(|o| o.host == "10.0.0.1" && o.port == 23));
    }

    #[test]
    fn explicit_password_is_the_only_candidate() {
        let list = Ont::candidates("10.0.0.1".into(), 23, None, Some("secret".into()));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].user, "root"); // defaults to the known telnet user
        assert_eq!(list[0].password, "secret");
    }

    #[test]
    fn custom_user_without_password_tries_default_passwords() {
        let list = Ont::candidates("10.0.0.1".into(), 23, Some("admin".into()), None);
        assert!(!list.is_empty());
        assert!(list.iter().all(|o| o.user == "admin"));
    }
}
