use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use md5::{Digest, Md5};
use uuid::Uuid;

type Parameters = HashMap<String, String>;

fn parameters(header: &str) -> Result<Parameters> {
    let (scheme, mut rest) = header
        .trim()
        .split_once(char::is_whitespace)
        .context("missing Digest parameters")?;
    ensure!(
        scheme.eq_ignore_ascii_case("digest"),
        "unsupported authentication scheme"
    );
    let mut fields = HashMap::new();
    while !rest.trim_start_matches([',', ' ', '\t']).is_empty() {
        rest = rest.trim_start_matches([',', ' ', '\t']);
        let (key, after_key) = rest.split_once('=').context("malformed Digest parameter")?;
        let after_key = after_key.trim_start();
        let (value, after_value) = if let Some(quoted) = after_key.strip_prefix('"') {
            let mut escaped = false;
            let mut value = String::new();
            let mut end = None;
            for (offset, ch) in quoted.char_indices() {
                if !escaped && ch == '"' {
                    end = Some(offset + 1);
                    break;
                }
                if !escaped && ch == '\\' {
                    escaped = true;
                } else {
                    value.push(ch);
                    escaped = false;
                }
            }
            (
                value,
                &quoted[end.context("unterminated Digest parameter")?..],
            )
        } else {
            let (value, next) = after_key.split_once(',').unwrap_or((after_key, ""));
            (value.trim().to_owned(), next)
        };
        fields.insert(key.trim().to_ascii_lowercase(), value);
        rest = after_value;
    }
    Ok(fields)
}

fn hash(value: &str) -> String {
    format!("{:x}", Md5::digest(value.as_bytes()))
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn response(
    challenge: &str,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Result<String> {
    let fields = parameters(challenge)?;
    let realm = fields
        .get("realm")
        .context("Digest challenge has no realm")?;
    let nonce = fields
        .get("nonce")
        .filter(|value| !value.is_empty())
        .context("Digest challenge has no nonce")?;
    let algorithm = fields.get("algorithm").map_or("MD5", String::as_str);
    ensure!(
        algorithm.eq_ignore_ascii_case("MD5") || algorithm.eq_ignore_ascii_case("MD5-sess"),
        "unsupported Digest algorithm"
    );
    let cnonce = Uuid::new_v4().simple().to_string();
    let mut ha1 = hash(&format!("{user}:{realm}:{password}"));
    let session = algorithm.eq_ignore_ascii_case("MD5-sess");
    if session {
        ha1 = hash(&format!("{ha1}:{nonce}:{cnonce}"));
    }
    let ha2 = hash(&format!("{method}:{uri}"));
    let (proof, extra) = if let Some(qop) = fields.get("qop").filter(|qop| !qop.is_empty()) {
        ensure!(
            qop.split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("auth")),
            "Digest server does not support qop=auth"
        );
        (
            hash(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")),
            format!(", qop=auth, nc=00000001, cnonce=\"{cnonce}\""),
        )
    } else {
        let extra = if session {
            format!(", cnonce=\"{cnonce}\"")
        } else {
            String::new()
        };
        (hash(&format!("{ha1}:{nonce}:{ha2}")), extra)
    };
    let opaque = fields
        .get("opaque")
        .map_or_else(String::new, |value| format!(", opaque={}", quote(value)));
    let prefix = format!(
        "Digest username={}, realm={}, nonce={}, uri={}",
        quote(user),
        quote(realm),
        quote(nonce),
        quote(uri)
    );
    let proof = format!(", response=\"{proof}\", algorithm={algorithm}");
    if method == "REGISTER" {
        Ok(format!("{prefix}{extra}{proof}{opaque}"))
    } else {
        Ok(format!("{prefix}{proof}{extra}{opaque}"))
    }
}

pub fn registration_probe(user: &str, password: &str, realm: &str, uri: &str) -> String {
    let ha1 = hash(&format!("{user}:{realm}:{password}"));
    let ha2 = hash(&format!("REGISTER:{uri}"));
    let proof = hash(&format!("{ha1}:::{ha2}"));
    format!(
        "Digest username={}, realm={}, nonce=\"\", uri={}, response=\"{proof}\", algorithm=MD5",
        quote(user),
        quote(realm),
        quote(uri)
    )
}
