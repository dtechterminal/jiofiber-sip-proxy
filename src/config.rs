use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use anyhow::{Context, Result, ensure};
use md5::{Digest, Md5};

pub const USER_AGENT: &str = "JCOW414/JUICEJFV-1.3.31";

/// The RJIL device token / SIP instance id is `md5(serial)` rendered as an upper-case
/// UUID inside `<urn:uuid:…>`, so the serial alone determines it — no separate secret.
fn token_from_serial(serial: &str) -> String {
    let hex = format!("{:x}", Md5::digest(serial.as_bytes())).to_uppercase();
    format!(
        "<urn:uuid:{}-{}-{}-{}-{}>",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32],
    )
}

/// The device token: `DEVICE_TOKEN` when set, otherwise derived from `DEVICE_SERIAL`.
pub fn device_token() -> Option<String> {
    optional("DEVICE_TOKEN").or_else(|| optional("DEVICE_SERIAL").map(|s| token_from_serial(&s)))
}

pub fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn parsed<T: FromStr>(name: &str) -> Result<Option<T>> {
    optional(name)
        .map(|value| {
            value
                .parse()
                .ok()
                .with_context(|| format!("invalid {name}"))
        })
        .transpose()
}

pub fn insecure_tls() -> Result<bool> {
    match optional("TLS_INSECURE").as_deref() {
        None | Some("0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        _ => anyhow::bail!("TLS_INSECURE must be 0 or 1"),
    }
}

#[derive(Clone)]
pub struct Device {
    pub serial: String,
    pub model: String,
    /// The line number. Empty when `DEVICE_MSISDN` is unset, in which case the
    /// provisioner discovers it from the ACS via a TR-069 bootstrap.
    pub msisdn: String,
    pub token: String,
    pub password: String,
    pub software: String,
    pub ccs_source: Ipv6Addr,
    pub acs_source: Ipv4Addr,
}

impl Device {
    /// Build the device identity from the environment, falling back to values read from the
    /// ONT over telnet (see [`crate::ont::discover`]). An explicit `DEVICE_*` env var always
    /// wins over the discovered value, so a user can override anything the ONT reports.
    pub fn resolve(
        serial: Option<String>,
        model: Option<String>,
        password: Option<String>,
    ) -> Result<Self> {
        let serial = optional("DEVICE_SERIAL").or(serial).context(
            "no device serial — set DEVICE_SERIAL, or ONT_HOST so it can be read from the ONT",
        )?;
        let password = optional("TR069_PASSWORD").or(password).context(
            "no TR-069 password — set TR069_PASSWORD, or ONT_HOST so it can be read from the ONT",
        )?;
        let token = optional("DEVICE_TOKEN").unwrap_or_else(|| token_from_serial(&serial));
        Ok(Self {
            model: optional("DEVICE_MODEL")
                .or(model)
                .unwrap_or_else(|| "JCOW414".into()),
            msisdn: optional("DEVICE_MSISDN").unwrap_or_default(),
            password,
            software: optional("DEVICE_SW_VER").unwrap_or_else(|| "R2.57".into()),
            ccs_source: parsed("CCS_SOURCE_IPV6")?.unwrap_or(Ipv6Addr::UNSPECIFIED),
            acs_source: parsed("ACS_SOURCE_IPV4")?.unwrap_or(Ipv4Addr::UNSPECIFIED),
            serial,
            token,
        })
    }
}

pub struct SipConfig {
    pub auth_user: String,
    pub password: String,
    pub realm: String,
    pub public_id: String,
    pub registrar: String,
    pub proxy: String,
}

impl SipConfig {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("SIP_AUTH_USER", &self.auth_user),
            ("SIP_PASSWORD", &self.password),
            ("SIP_REALM", &self.realm),
            ("PUBLIC_ID", &self.public_id),
            ("REGISTRAR_HOST", &self.registrar),
            ("PROXY_HOST", &self.proxy),
        ] {
            ensure!(
                !value.trim().is_empty() && !value.chars().any(char::is_control),
                "invalid {name}"
            );
        }
        ensure!(
            self.public_id.starts_with("sip:")
                && self.public_id.contains('@')
                && !self.public_id.contains(['<', '>', ' ']),
            "PUBLIC_ID must be a SIP URI"
        );
        ensure!(
            !self.registrar.contains(['<', '>', ' ', '/', '@']),
            "invalid REGISTRAR_HOST"
        );
        Ok(())
    }

    pub fn domain(&self) -> &str {
        self.public_id
            .rsplit_once('@')
            .map_or(&self.registrar, |(_, host)| {
                host.split(';').next().unwrap_or(host)
            })
    }

    pub fn print(&self) {
        println!(
            "SIP_AUTH_USER={}\nSIP_PASSWORD={}\nSIP_REALM={}\nPUBLIC_ID={}\nREGISTRAR_HOST={}\nPROXY_HOST={}",
            self.auth_user, self.password, self.realm, self.public_id, self.registrar, self.proxy
        );
    }
}

pub struct Network {
    pub local_port: u16,
    pub rtp_port: u16,
    pub bind: IpAddr,
    pub advertise: Option<IpAddr>,
    pub upstream_source: Ipv6Addr,
    pub destination: Option<String>,
    pub instance: Option<String>,
    pub insecure: bool,
    pub debug_register: bool,
}

impl Network {
    pub fn from_env() -> Result<Self> {
        let instance = device_token();
        if let Some(token) = &instance {
            ensure!(
                !token.contains('"') && !token.chars().any(char::is_control),
                "invalid DEVICE_TOKEN for SIP instance"
            );
        }
        Ok(Self {
            local_port: parsed("LOCAL_PORT")?.unwrap_or(5061),
            rtp_port: parsed("RTP_PORT")?.unwrap_or(52000),
            bind: parsed("LOCAL_BIND")?.unwrap_or(Ipv4Addr::LOCALHOST.into()),
            advertise: parsed("LOCAL_ADVERTISE_IP")?,
            upstream_source: parsed("SIP_SOURCE_IPV6")?.unwrap_or(Ipv6Addr::UNSPECIFIED),
            destination: optional("DEST_TO_LOCAL"),
            instance,
            insecure: insecure_tls()?,
            debug_register: optional("SIP_DEBUG_REGISTER").as_deref() == Some("1"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::token_from_serial;

    #[test]
    fn token_is_md5_of_serial_as_upper_uuid() {
        // md5("test") = 098f6bcd4621d373cade4e832627b4f6
        assert_eq!(
            token_from_serial("test"),
            "<urn:uuid:098F6BCD-4621-D373-CADE-4E832627B4F6>"
        );
    }
}
