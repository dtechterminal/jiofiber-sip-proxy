use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use quick_xml::{
    Reader,
    escape::{escape, unescape},
    events::Event,
};
use reqwest::{
    Client, Response, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderMap, SET_COOKIE, WWW_AUTHENTICATE},
};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use tokio::{
    net::lookup_host,
    time::{sleep, timeout},
};

use crate::{
    config::{Device, SipConfig, USER_AGENT},
    digest,
};

const CCS_HOST: &str = "ue.wln.ccs.jio.com";
const ACS_HOST: &str = "acs.oss.jio.com";
const ACS_ADDRESS: &str = "49.40.134.113:8443";
const ACS_PATH: &str = "/ftacs-digest/ACS";
const COOKIE_NAME: &str = "WITRCSeConfigCookie";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const CWMP: &str = "urn:dslforum-org:cwmp-1-0";

fn http(source: IpAddr, insecure: bool) -> reqwest::ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .local_address(source)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(insecure)
        .https_only(true)
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
}

struct Ccs {
    http: Client,
    url: String,
}

impl Ccs {
    async fn connect(device: &Device, insecure: bool) -> Result<Self> {
        let addrs: Vec<_> = timeout(Duration::from_secs(5), lookup_host((CCS_HOST, 443)))
            .await
            .context("CCS DNS lookup timed out")?
            .context("resolving CCS")?
            .filter(SocketAddr::is_ipv6)
            .collect();
        ensure!(!addrs.is_empty(), "CCS has no IPv6 address");
        Ok(Self {
            http: http(device.ccs_source.into(), insecure)
                .resolve_to_addrs(CCS_HOST, &addrs)
                .user_agent(USER_AGENT)
                .build()?,
            url: format!("https://{CCS_HOST}/"),
        })
    }

    async fn get(&self, device: &Device, otp: Option<(&str, &str)>) -> Result<Response> {
        let params = [
            ("rjil_token", device.token.as_str()),
            ("serialNumber", &device.serial),
            ("terminal_model", &device.model),
            ("terminal_sw_version", &device.software),
            ("msisdn", &device.msisdn),
            ("terminal_vendor", "FX"),
            ("client_version", "HGWVoice-3.0"),
            ("SMS_port", "0"),
            ("rcs_version", "5.1B"),
            ("client_vendor", "WITS"),
            ("rcs_profile", "joyn_blackbird"),
            ("sim_mode", "2"),
            ("vers", "0"),
            ("token", ""),
            ("sub_version", "0"),
        ];
        let mut request = self.http.get(&self.url).query(&params);
        if let Some((otp, cookie)) = otp {
            request = request.query(&[("OTP", otp)]).header(COOKIE, cookie);
        }
        request
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("CCS request failed")
    }
}

fn cookies(headers: &HeaderMap) -> impl DoubleEndedIterator<Item = (&str, &str)> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next()?.split_once('='))
}

struct Acs<'a> {
    http: Client,
    url: String,
    device: &'a Device,
    cookies: HashMap<String, String>,
}

impl<'a> Acs<'a> {
    fn new(device: &'a Device, insecure: bool) -> Result<Self> {
        let address: SocketAddr = ACS_ADDRESS.parse()?;
        Ok(Self {
            http: http(device.acs_source.into(), insecure)
                .resolve(ACS_HOST, address)
                .build()?,
            url: format!("https://{ACS_HOST}:{}{ACS_PATH}", address.port()),
            device,
            cookies: HashMap::new(),
        })
    }

    async fn post(&mut self, body: &str, auth: Option<&str>) -> Result<Response> {
        let mut request = self
            .http
            .post(&self.url)
            .header(CONTENT_TYPE, "text/xml; charset=utf-8")
            .header("SOAPAction", "\"\"")
            .body(body.to_owned());
        if !self.cookies.is_empty() {
            let cookie = self
                .cookies
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(COOKIE, cookie);
        }
        if let Some(auth) = auth {
            request = request.header(AUTHORIZATION, auth);
        }
        let response = request.send().await.context("ACS request failed")?;
        for (key, value) in cookies(response.headers()) {
            self.cookies.insert(key.to_owned(), value.to_owned());
        }
        Ok(response)
    }

    async fn exchange(&mut self, body: &str) -> Result<(StatusCode, String)> {
        let mut response = self.post(body, None).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let header = response
                .headers()
                .get_all(WWW_AUTHENTICATE)
                .iter()
                .filter_map(|header| header.to_str().ok())
                .find(|header| {
                    header
                        .get(..7)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Digest "))
                })
                .context("ACS did not provide a Digest challenge")?;
            let auth = digest::response(
                header,
                &self.device.serial,
                &self.device.password,
                "POST",
                ACS_PATH,
            )?;
            response = self.post(body, Some(&auth)).await?;
        }
        let status = response.status();
        ensure!(status.is_success(), "ACS returned HTTP {status}");
        Ok((
            status,
            response.text().await.context("reading ACS response")?,
        ))
    }

    async fn otp(&mut self) -> Result<String> {
        self.cookies.clear();
        let (status, _) = self.exchange(&inform(self.device, "1 BOOT")?).await?;
        ensure!(status == StatusCode::OK, "ACS did not accept Inform");
        let mut request = String::new();
        let mut otp = None;
        for _ in 0..10 {
            let (status, body) = self.exchange(&request).await?;
            if status == StatusCode::NO_CONTENT || (body.trim().is_empty() && request.is_empty()) {
                break;
            }
            request.clear();
            if body.trim().is_empty() {
                continue;
            }
            let rpc = Rpc::parse(&body)?;
            let id = if rpc.id.is_empty() {
                "1"
            } else {
                rpc.id.trim()
            };
            if rpc.set {
                if let Some(value) = rpc.code {
                    otp = Some(value);
                }
                request = envelope(
                    id,
                    "<C:SetParameterValuesResponse><Status>0</Status></C:SetParameterValuesResponse>",
                );
            } else if rpc.get {
                let name = rpc.names.first().map_or("", String::as_str);
                let value = otp
                    .as_deref()
                    .filter(|_| name.contains("Verif"))
                    .unwrap_or("");
                request = envelope(
                    id,
                    &format!(
                        r#"<C:GetParameterValuesResponse><ParameterList E:arrayType="C:ParameterValueStruct[1]"><ParameterValueStruct><Name>{}</Name><Value I:type="D:string">{}</Value></ParameterValueStruct></ParameterList></C:GetParameterValuesResponse>"#,
                        escape(name),
                        escape(value)
                    ),
                );
            }
        }
        otp.context("ACS did not supply a verification code")
    }

    /// Discovers the line number (MSISDN) from the ACS. A `0 BOOTSTRAP` Inform — what a
    /// factory-fresh ONT sends — makes the ACS push the full line config, including
    /// `Device.X_RJIL_FixedVoice.FLN` (the number). Used when `DEVICE_MSISDN` is unset.
    async fn discover_msisdn(&mut self) -> Result<String> {
        self.cookies.clear();
        let (status, _) = self.exchange(&inform(self.device, "0 BOOTSTRAP")?).await?;
        ensure!(
            status == StatusCode::OK,
            "ACS did not accept bootstrap Inform"
        );
        let mut request = String::new();
        for _ in 0..12 {
            let (status, body) = self.exchange(&request).await?;
            request.clear();
            if status == StatusCode::NO_CONTENT || body.trim().is_empty() {
                break;
            }
            let rpc = Rpc::parse(&body)?;
            if let Some(fln) = rpc.fln {
                let fln = fln.trim().to_owned();
                ensure!(!fln.is_empty(), "ACS returned an empty line number");
                return Ok(fln);
            }
            let id = if rpc.id.is_empty() {
                "1"
            } else {
                rpc.id.trim()
            };
            if rpc.set {
                request = envelope(
                    id,
                    "<C:SetParameterValuesResponse><Status>0</Status></C:SetParameterValuesResponse>",
                );
            } else if rpc.get {
                let count = rpc.names.len().max(1);
                let structs: String = rpc
                    .names
                    .iter()
                    .map(|name| {
                        format!(
                            r#"<ParameterValueStruct><Name>{}</Name><Value I:type="D:string"></Value></ParameterValueStruct>"#,
                            escape(name)
                        )
                    })
                    .collect();
                request = envelope(
                    id,
                    &format!(
                        r#"<C:GetParameterValuesResponse><ParameterList E:arrayType="C:ParameterValueStruct[{count}]">{structs}</ParameterList></C:GetParameterValuesResponse>"#
                    ),
                );
            } else {
                break;
            }
        }
        bail!("ACS did not provide the line number (FLN) on bootstrap")
    }
}

fn envelope(id: &str, body: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<S:Envelope xmlns:S="{SOAP}" xmlns:C="{CWMP}" xmlns:E="http://schemas.xmlsoap.org/soap/encoding/" xmlns:I="http://www.w3.org/2001/XMLSchema-instance" xmlns:D="http://www.w3.org/2001/XMLSchema"><S:Header><C:ID S:mustUnderstand="1">{}</C:ID></S:Header><S:Body>{body}</S:Body></S:Envelope>"#,
        escape(id)
    )
}

fn inform(device: &Device, event: &str) -> Result<String> {
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)?
        .format(&Iso8601::DEFAULT)?;
    let now = now.replace(".000000000", "");
    Ok(envelope(
        "1",
        &format!(
            r#"<C:Inform>
<DeviceId><Manufacturer>Sercomm</Manufacturer><OUI>001D68</OUI><ProductClass>{}</ProductClass><SerialNumber>{}</SerialNumber></DeviceId>
<Event E:arrayType="C:EventStruct[1]"><EventStruct><EventCode>{event}</EventCode><CommandKey/></EventStruct></Event>
<MaxEnvelopes>1</MaxEnvelopes><CurrentTime>{now}</CurrentTime><RetryCount>0</RetryCount>
<ParameterList E:arrayType="C:ParameterValueStruct[2]">
<ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name><Value I:type="D:string">{}</Value></ParameterValueStruct>
<ParameterValueStruct><Name>Device.ManagementServer.ConnectionRequestURL</Name><Value I:type="D:string">http://192.168.0.51:7547/</Value></ParameterValueStruct>
</ParameterList></C:Inform>"#,
            escape(&device.model),
            escape(&device.serial),
            escape(&device.software)
        ),
    ))
}

#[derive(Default)]
struct Rpc {
    id: String,
    code: Option<String>,
    fln: Option<String>,
    names: Vec<String>,
    set: bool,
    get: bool,
}

impl Rpc {
    fn parse(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        let mut rpc = Self::default();
        let mut path = Vec::new();
        let mut param_name = String::new();
        let mut param_value = String::new();
        let mut value = String::new();
        loop {
            match reader.read_event()? {
                Event::Start(tag) => {
                    let name = tag.local_name();
                    match name.as_ref() {
                        b"SetParameterValues" => rpc.set = true,
                        b"GetParameterValues" => rpc.get = true,
                        b"ParameterValueStruct" => {
                            param_name.clear();
                            param_value.clear();
                        }
                        _ => {}
                    }
                    path.push(name.as_ref().to_vec());
                    value.clear();
                }
                Event::Text(text) => value.push_str(&text.xml10_content()?),
                Event::CData(text) => value.push_str(&text.xml10_content()?),
                Event::GeneralRef(reference) => {
                    let reference = format!("&{};", reference.decode()?);
                    value.push_str(&unescape(&reference)?);
                }
                Event::End(tag) => {
                    match tag.local_name().as_ref() {
                        b"ID" => rpc.id = value.clone(),
                        b"Name" => param_name = value.trim().into(),
                        b"Value" => param_value = value.trim().into(),
                        b"string" if rpc.get => rpc.names.push(value.trim().into()),
                        b"ParameterValueStruct"
                            if rpc.set
                                && param_name.ends_with("VerificationCode")
                                && !param_value.is_empty() =>
                        {
                            rpc.code = Some(param_value.clone());
                        }
                        b"ParameterValueStruct"
                            if rpc.set
                                && param_name.ends_with("FLN")
                                && !param_value.is_empty() =>
                        {
                            rpc.fln = Some(param_value.clone());
                        }
                        _ => {}
                    }
                    path.pop();
                    value.clear();
                }
                Event::Eof => {
                    ensure!(path.is_empty(), "incomplete ACS SOAP envelope");
                    return Ok(rpc);
                }
                _ => {}
            }
        }
    }
}

fn profile(xml: &str) -> Result<SipConfig> {
    let mut reader = Reader::from_str(xml);
    let mut params = HashMap::new();
    loop {
        match reader.read_event()? {
            Event::Start(tag) | Event::Empty(tag) if tag.local_name().as_ref() == b"parm" => {
                let mut name = None;
                let mut value = None;
                for attr in tag.attributes() {
                    let attr = attr?;
                    match attr.key.local_name().as_ref() {
                        b"name" => {
                            name = Some(
                                attr.decode_and_unescape_value(reader.decoder())?
                                    .into_owned(),
                            )
                        }
                        b"value" => {
                            value = Some(
                                attr.decode_and_unescape_value(reader.decoder())?
                                    .into_owned(),
                            )
                        }
                        _ => {}
                    }
                }
                if let (Some(name), Some(value)) = (name, value) {
                    params.insert(name, value);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let get = |name| params.get(name).filter(|value| !value.is_empty()).cloned();
    let registrar = get("Home_network_domain_name").context("CCS profile has no home domain")?;
    let public_id =
        get("Public_User_Identity").context("CCS profile has no public SIP identity")?;
    let cfg = SipConfig {
        auth_user: get("UserName")
            .or_else(|| get("Private_User_Identity"))
            .context("CCS profile has no auth user")?,
        password: get("UserPwd").context("CCS profile has no SIP password")?,
        realm: get("Realm").unwrap_or_else(|| registrar.clone()),
        public_id: if public_id.starts_with("sip:") {
            public_id
        } else {
            format!("sip:{public_id}")
        },
        registrar,
        proxy: get("Address").context("CCS profile has no proxy address")?,
    };
    cfg.validate()?;
    Ok(cfg)
}

async fn attempt(ccs: &Ccs, acs: &mut Acs<'_>) -> Result<SipConfig> {
    let response = ccs.get(acs.device, None).await?;
    let cookie = cookies(response.headers())
        .rfind(|(name, value)| *name == COOKIE_NAME && !value.is_empty())
        .map(|(name, value)| format!("{name}={value}"))
        .with_context(|| {
            format!(
                "CCS trigger returned HTTP {} without a session cookie",
                response.status()
            )
        })?;
    let otp = acs.otp().await?;
    sleep(Duration::from_secs(1)).await;
    let response = ccs.get(acs.device, Some((&otp, &cookie))).await?;
    ensure!(
        response.status().is_success(),
        "CCS profile returned HTTP {}",
        response.status()
    );
    let xml = response
        .text()
        .await
        .map_err(reqwest::Error::without_url)
        .context("reading CCS profile")?;
    profile(&xml).context("invalid CCS SIP profile")
}

pub async fn provision(device: &Device, insecure: bool) -> Result<SipConfig> {
    // The MSISDN is a required CCS input; when it is not supplied, recover it from the
    // ACS first (it is bound to the serial in Jio's backend and pushed on a bootstrap).
    let mut owned;
    let device = if device.msisdn.is_empty() {
        let msisdn = Acs::new(device, insecure)?
            .discover_msisdn()
            .await
            .context(
                "discovering the line number via TR-069 bootstrap (set DEVICE_MSISDN to skip)",
            )?;
        eprintln!("Discovered line number from the ACS");
        owned = device.clone();
        owned.msisdn = msisdn;
        &owned
    } else {
        device
    };
    let ccs = Ccs::connect(device, insecure).await?;
    let mut acs = Acs::new(device, insecure)?;
    for number in 1..=3 {
        match attempt(&ccs, &mut acs).await {
            Ok(config) => return Ok(config),
            Err(error) if number == 3 => {
                return Err(error).context("provisioning failed after three attempts");
            }
            Err(error) => eprintln!("Provisioning attempt {number} failed: {error}"),
        }
        sleep(Duration::from_secs(3)).await;
    }
    bail!("provisioning failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };

    async fn request(listener: &TcpListener) -> Result<(TcpStream, String, String)> {
        let (stream, _) = listener.accept().await?;
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            ensure!(
                reader.read_line(&mut line).await? != 0,
                "truncated HTTP request"
            );
            if line == "\r\n" {
                break;
            }
            headers.push_str(&line);
        }
        let mut body = vec![
            0;
            headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("Content-Length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0)
        ];
        reader.read_exact(&mut body).await?;
        Ok((reader.into_inner(), headers, String::from_utf8(body)?))
    }

    async fn reply(stream: &mut TcpStream, status: &str, headers: &str, body: &str) -> Result<()> {
        let response = format!(
            "HTTP/1.1 {status}\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        Ok(())
    }

    #[test]
    fn rpc_parse_extracts_the_line_number() {
        let body = concat!(
            r#"<S:Envelope xmlns:S="s" xmlns:C="c"><S:Header><C:ID>7</C:ID></S:Header>"#,
            r#"<S:Body><C:SetParameterValues><ParameterList>"#,
            r#"<ParameterValueStruct><Name>Device.X_RJIL_FixedVoice.FLN</Name><Value>+910000000001</Value></ParameterValueStruct>"#,
            r#"</ParameterList></C:SetParameterValues></S:Body></S:Envelope>"#,
        );
        let rpc = Rpc::parse(body).unwrap();
        assert!(rpc.set);
        assert_eq!(rpc.fln.as_deref(), Some("+910000000001"));
    }

    #[tokio::test]
    async fn provisions_from_ccs_cookie_and_challenged_acs_session() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let device = Device {
            serial: "test-serial".into(),
            model: "TEST".into(),
            msisdn: "+911234567890".into(),
            token: "<test+token>".into(),
            password: "fake-password".into(),
            software: "R0".into(),
            ccs_source: "::1".parse()?,
            acs_source: "127.0.0.1".parse()?,
        };
        let http = Client::builder().no_proxy().build()?;
        let ccs = Ccs {
            http: http.clone(),
            url: url.clone(),
        };
        let mut acs = Acs {
            http,
            url: format!("{url}{ACS_PATH}"),
            device: &device,
            cookies: HashMap::new(),
        };
        let server = async {
            let (mut conn, headers, _) = request(&listener).await?;
            assert!(
                headers.starts_with("GET /?") && headers.contains("rjil_token=%3Ctest%2Btoken%3E")
            );
            reply(
                &mut conn,
                "200 OK",
                "Set-Cookie: WITRCSeConfigCookie=synthetic; Path=/\r\n",
                "",
            )
            .await?;

            let (mut conn, headers, body) = request(&listener).await?;
            assert!(headers.starts_with("POST /ftacs-digest/ACS "));
            assert!(body.contains("<SerialNumber>test-serial</SerialNumber>"));
            reply(&mut conn, "401 Unauthorized", "WWW-Authenticate: Digest realm=\"acs\", nonce=\"fixture\", qop=\"auth\"\r\nSet-Cookie: acs=sess\r\n", "").await?;

            let (mut conn, headers, body) = request(&listener).await?;
            assert!(headers.contains("authorization: Digest username=\"test-serial\""));
            assert!(headers.contains("cookie: acs=sess"));
            assert!(body.contains("<C:Inform>"));
            reply(
                &mut conn,
                "200 OK",
                "",
                "<Envelope><InformResponse/></Envelope>",
            )
            .await?;

            let (mut conn, _, body) = request(&listener).await?;
            assert!(body.is_empty());
            let set = r#"<S:Envelope xmlns:S="soap" xmlns:C="cwmp"><S:Header><C:ID>12</C:ID></S:Header><S:Body><C:SetParameterValues><ParameterList><ParameterValueStruct><Name>Root.VerificationCode</Name><Value>452&#55;</Value></ParameterValueStruct></ParameterList></C:SetParameterValues></S:Body></S:Envelope>"#;
            reply(&mut conn, "200 OK", "", set).await?;

            let (mut conn, _, body) = request(&listener).await?;
            assert!(body.contains("<C:SetParameterValuesResponse>") && body.contains(">12</C:ID>"));
            let get = r#"<S:Envelope xmlns:S="soap" xmlns:C="cwmp"><S:Header><C:ID>13</C:ID></S:Header><S:Body><C:GetParameterValues><ParameterNames><string>Root.VerificationCode</string></ParameterNames></C:GetParameterValues></S:Body></S:Envelope>"#;
            reply(&mut conn, "200 OK", "", get).await?;

            let (mut conn, _, body) = request(&listener).await?;
            assert!(
                body.contains("<C:GetParameterValuesResponse>")
                    && body.contains(">13</C:ID>")
                    && body.contains(">4527</Value>")
            );
            reply(&mut conn, "204 No Content", "", "").await?;

            let (mut conn, headers, _) = request(&listener).await?;
            assert!(
                headers.contains("&OTP=4527 ")
                    && headers.contains("cookie: WITRCSeConfigCookie=synthetic")
            );
            let profile = r#"<configuration>
                <parm value="fixture@example.test" name="Private_User_Identity"/>
                <parm name="Public_User_Identity" value="sip:+911234567890@example.test"/>
                <parm name="Home_network_domain_name" value="example.test"/>
                <parm name="Address" value="proxy.example.test:5071"/>
                <parm name="UserPwd" value="sip&amp;test"/>
            </configuration>"#;
            reply(&mut conn, "200 OK", "", profile).await?;
            Ok::<_, anyhow::Error>(())
        };
        let (config, _) = timeout(Duration::from_secs(5), async {
            tokio::try_join!(attempt(&ccs, &mut acs), server)
        })
        .await??;
        assert_eq!(config.auth_user, "fixture@example.test");
        assert_eq!(config.password, "sip&test");
        assert_eq!(config.realm, "example.test");
        assert_eq!(config.proxy, "proxy.example.test:5071");
        Ok(())
    }
}
