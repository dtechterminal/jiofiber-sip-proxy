//! A tiny local admin server so the setup wizard can configure a *running* proxy.
//!
//! When `ADMIN_BIND` is set the proxy serves the wizard (`src/admin_ui.html`) and three
//! endpoints on that address:
//!
//! * `GET  /api/config`   — the current `sip.env`, to prefill the form.
//! * `POST /api/discover` — telnet into the ONT with the creds in the body and report what
//!   it can read (serial, model, whether the TR-069 password is present), plus the host's
//!   own line `/64`. Read-only.
//! * `POST /api/apply`    — write the posted `sip.env` to the config file and signal a
//!   live reload (the supervisor in `main` re-provisions without a process restart).
//!
//! The listener handles secrets, so it binds to loopback by default and refuses to bind to
//! anything else without `ADMIN_TOKEN`. The token (when set) gates every route and is
//! injected into the served page so its own requests carry it.

use std::{
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

use crate::{config, ont};

const UI_HTML: &str = include_str!("admin_ui.html");

/// Every `sip.env` key the wizard knows about, used to rebuild the file from the live env
/// the first time (before anything has been applied).
const KNOWN_KEYS: &[&str] = &[
    "DEVICE_SERIAL",
    "TR069_PASSWORD",
    "DEVICE_MSISDN",
    "DEVICE_MODEL",
    "DEVICE_SW_VER",
    "DEVICE_TOKEN",
    "ONT_HOST",
    "ONT_TELNET_PASSWORD",
    "ONT_TELNET_USER",
    "ONT_TELNET_PORT",
    "ONT_DISABLE_VOICE",
    "CCS_SOURCE_IPV6",
    "ACS_SOURCE_IPV4",
    "SIP_SOURCE_IPV6",
    "LOCAL_BIND",
    "LOCAL_ADVERTISE_IP",
    "LOCAL_PORT",
    "RTP_PORT",
    "DEST_TO_LOCAL",
    "TLS_INSECURE",
    "SIP_DEBUG_REGISTER",
];

/// Where applied config is persisted. Mount a volume here to keep it across container
/// recreation; within one container's life a reload works regardless.
pub fn config_file_path() -> PathBuf {
    config::optional("CONFIG_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data/sip.env"))
}

/// Load a `KEY=VALUE` config file into the process environment, so the next provision cycle
/// picks it up. An applied file therefore overrides whatever the container started with.
pub fn load_config_file(path: &Path) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let (key, value) = (key.trim(), value.trim());
            if !key.is_empty() {
                // Runs only at the top of the supervisor loop, while no bridge is reading
                // env, so this global mutation is sequenced safely.
                unsafe { std::env::set_var(key, value) };
            }
        }
    }
}

pub struct Admin {
    bind: SocketAddr,
    token: Option<String>,
    config_file: PathBuf,
}

impl Admin {
    pub fn from_env() -> Result<Option<Self>> {
        let Some(bind) = config::optional("ADMIN_BIND") else {
            return Ok(None);
        };
        let bind: SocketAddr = bind
            .parse()
            .with_context(|| format!("ADMIN_BIND must be host:port (got {bind:?})"))?;
        let token = config::optional("ADMIN_TOKEN").filter(|t| !t.is_empty());
        if !bind.ip().is_loopback() && token.is_none() {
            bail!(
                "ADMIN_BIND={bind} is not loopback but ADMIN_TOKEN is unset — refusing to \
                 expose the admin UI (which holds secrets) without a token"
            );
        }
        Ok(Some(Self {
            bind,
            token,
            config_file: config_file_path(),
        }))
    }

    pub async fn serve(self: Arc<Self>, reload: Arc<Notify>) -> Result<()> {
        let listener = TcpListener::bind(self.bind)
            .await
            .with_context(|| format!("binding the admin server to {}", self.bind))?;
        let hint = if self.token.is_some() {
            "/?token=<ADMIN_TOKEN>"
        } else {
            "/"
        };
        eprintln!("admin UI: http://{}{hint}", self.bind);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let me = self.clone();
            let reload = reload.clone();
            tokio::spawn(async move {
                let _ = me.handle(stream, reload).await;
            });
        }
    }

    async fn handle(&self, mut stream: TcpStream, reload: Arc<Notify>) -> Result<()> {
        let Some(req) = read_request(&mut stream).await? else {
            return Ok(());
        };
        if !self.authorized(&req) {
            return respond(
                &mut stream,
                401,
                TEXT,
                b"unauthorized: missing or wrong token",
            )
            .await;
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => {
                respond(&mut stream, 200, HTML, self.page().as_bytes()).await
            }
            ("GET", "/api/config") => {
                respond(
                    &mut stream,
                    200,
                    TEXT,
                    current_config_text(&self.config_file).as_bytes(),
                )
                .await
            }
            ("GET", "/api/scan") => {
                let body = scan().await;
                respond(&mut stream, 200, TEXT, body.as_bytes()).await
            }
            ("POST", "/api/discover") => {
                let body = discover(&req.body).await;
                respond(&mut stream, 200, TEXT, body.as_bytes()).await
            }
            ("POST", "/api/apply") => self.apply(&mut stream, &req.body, &reload).await,
            _ => respond(&mut stream, 404, TEXT, b"not found").await,
        }
    }

    fn authorized(&self, req: &Request) -> bool {
        let Some(token) = &self.token else {
            return true;
        };
        if req
            .authorization
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            == Some(token.as_str())
        {
            return true;
        }
        req.query_token.as_deref() == Some(token.as_str())
    }

    fn page(&self) -> String {
        let inject = match &self.token {
            Some(t) => format!("<script>window.__ADMIN_TOKEN__={};</script>", js_string(t)),
            None => String::new(),
        };
        UI_HTML.replacen("<!--ADMIN_TOKEN-->", &inject, 1)
    }

    async fn apply(&self, stream: &mut TcpStream, body: &[u8], reload: &Notify) -> Result<()> {
        let text = String::from_utf8_lossy(body);
        let has = |key: &str| field(&text, key).is_some_and(|v| !v.is_empty());
        if !(has("ONT_HOST") || (has("DEVICE_SERIAL") && has("TR069_PASSWORD"))) {
            return respond(
                stream,
                400,
                TEXT,
                b"need ONT_HOST (so the proxy can read them) or DEVICE_SERIAL + TR069_PASSWORD",
            )
            .await;
        }
        if let Some(dir) = self.config_file.parent() {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
        let tmp = self.config_file.with_extension("tmp");
        tokio::fs::write(&tmp, text.as_bytes())
            .await
            .context("writing config file")?;
        tokio::fs::rename(&tmp, &self.config_file)
            .await
            .context("saving config file")?;
        reload.notify_one();
        respond(stream, 200, TEXT, b"ok").await
    }
}

/// Scan the LAN for a Jio ONT and report the first one found (address + what it reads off it).
/// Never fails the request — nothing found or an error comes back as `ok=no`.
async fn scan() -> String {
    let mut out = String::new();
    match ont::scan().await {
        Ok(Some(hit)) => {
            out.push_str("ok=yes\n");
            out.push_str(&format!("ONT_HOST={}\n", hit.host));
            if let Some(user) = hit.discovery.auth_user {
                out.push_str(&format!("auth_user={user}\n"));
            }
            if let Some(serial) = hit.discovery.serial {
                out.push_str(&format!("DEVICE_SERIAL={serial}\n"));
            }
            if let Some(model) = hit.discovery.model {
                out.push_str(&format!("DEVICE_MODEL={model}\n"));
            }
            out.push_str(&format!(
                "tr069_found={}\n",
                if hit.discovery.tr069_password.is_some() {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        Ok(None) => out.push_str("ok=no\nerror=no ONT found on the local network\n"),
        Err(error) => {
            out.push_str("ok=no\n");
            out.push_str(&format!("error={}\n", one_line(&format!("{error:#}"))));
        }
    }
    if let Some(prefix) = host_prefix64() {
        out.push_str(&format!("host_prefix64={prefix}\n"));
    }
    out
}

/// Telnet into the ONT named in the posted creds and report what can be read. Never fails the
/// request — a login problem comes back as `ok=no` with a message.
async fn discover(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let host = match field(&text, "ONT_HOST").filter(|h| !h.is_empty()) {
        Some(h) => h,
        None => return "ok=no\nerror=ONT_HOST is required\n".to_owned(),
    };
    let port = field(&text, "ONT_TELNET_PORT")
        .and_then(|p| p.parse().ok())
        .unwrap_or(23);
    // No password posted → try the known default logins; an explicit one is used as given.
    let targets = ont::Ont::candidates(
        host,
        port,
        field(&text, "ONT_TELNET_USER").filter(|u| !u.is_empty()),
        field(&text, "ONT_TELNET_PASSWORD").filter(|p| !p.is_empty()),
    );
    let mut out = String::new();
    match ont::discover(&targets).await {
        Ok(found) => {
            out.push_str("ok=yes\n");
            if let Some(user) = found.auth_user {
                out.push_str(&format!("auth_user={user}\n"));
            }
            if let Some(serial) = found.serial {
                out.push_str(&format!("DEVICE_SERIAL={serial}\n"));
            }
            if let Some(model) = found.model {
                out.push_str(&format!("DEVICE_MODEL={model}\n"));
            }
            // The password value stays on the device; the proxy re-reads it at provision time.
            out.push_str(&format!(
                "tr069_found={}\n",
                if found.tr069_password.is_some() {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        Err(error) => {
            out.push_str("ok=no\n");
            out.push_str(&format!("error={}\n", one_line(&format!("{error:#}"))));
        }
    }
    if let Some(prefix) = host_prefix64() {
        out.push_str(&format!("host_prefix64={prefix}\n"));
    }
    out
}

/// The current config as `sip.env` text: the applied file if present, else reconstructed
/// from the live environment so the form prefills with however the container was started.
fn current_config_text(path: &Path) -> String {
    if let Ok(saved) = std::fs::read_to_string(path) {
        return saved;
    }
    let mut out = String::from("# current config (from the environment)\n");
    for key in KNOWN_KEYS {
        if let Some(value) = config::optional(key).filter(|v| !v.is_empty()) {
            out.push_str(key);
            out.push('=');
            out.push_str(&value);
            out.push('\n');
        }
    }
    out
}

/// The host's own global IPv6 `/64`, read locally from `/proc/net/if_inet6` — this is the
/// prefix the proxy sources from, which in AP/bridge setups differs from the ONT's.
fn host_prefix64() -> Option<String> {
    let data = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in data.lines() {
        let mut cols = line.split_whitespace();
        let addr = cols.next()?;
        let _ifindex = cols.next();
        let _prefixlen = cols.next();
        let scope = cols.next()?;
        if scope != "00" || addr.len() != 32 {
            continue; // 00 == global scope
        }
        let mut segs = [0u16; 8];
        let mut ok = true;
        for (i, seg) in segs.iter_mut().enumerate() {
            match u16::from_str_radix(&addr[i * 4..i * 4 + 4], 16) {
                Ok(v) => *seg = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let ip = Ipv6Addr::from(segs);
        if ip.segments()[0] & 0xe000 == 0x2000 {
            // global unicast 2000::/3
            return Some(format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segs[0], segs[1], segs[2], segs[3]
            ));
        }
    }
    None
}

/// Find the trimmed value of a `KEY=...` line in env-style text.
fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|v| v.trim().to_owned())
    })
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Render a string as a JS string literal for safe injection into the page.
fn js_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\x3c"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

struct Request {
    method: String,
    path: String,
    query_token: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 64 * 1024 {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_owned();
    let target = request_line.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (path, query) = (path.to_owned(), query.to_owned());

    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                "authorization" => authorization = Some(value.trim().to_owned()),
                _ => {}
            }
        }
    }
    content_length = content_length.min(1 << 20);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    let query_token = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("token="))
        .map(|t| t.to_owned());
    Ok(Some(Request {
        method,
        path,
        query_token,
        authorization,
        body,
    }))
}

async fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_extracts_trimmed_values() {
        let text = "# comment\nONT_HOST=192.168.0.51\nONT_TELNET_PORT= 23 \nEMPTY=\n";
        assert_eq!(field(text, "ONT_HOST").as_deref(), Some("192.168.0.51"));
        assert_eq!(field(text, "ONT_TELNET_PORT").as_deref(), Some("23"));
        assert_eq!(field(text, "EMPTY").as_deref(), Some(""));
        assert_eq!(field(text, "MISSING"), None);
    }

    #[test]
    fn js_string_escapes_breakouts() {
        assert_eq!(js_string("abc123"), "\"abc123\"");
        assert!(js_string("a\"</script>").contains("\\x3c"));
        assert!(js_string("a\"b").contains("\\\""));
    }

    #[test]
    fn the_page_has_a_token_slot() {
        assert!(UI_HTML.contains("<!--ADMIN_TOKEN-->"));
    }
}
