# JioFiber SIP Proxy — Port to Rust

> **Historical porting brief.** This is the spec the Rust port was originally built from, kept for reference. For the delivered software, `Cargo.toml` is authoritative for dependencies and `README.md` for behaviour, configuration, and the third-party-software list. Some choices below changed during implementation — notably the IMS SIP leg uses `native-tls`/OpenSSL (not rustls) for its legacy cipher, DNS uses `hickory-resolver`, SIP is hand-rolled (not `rsip`), and the build also targets `aarch64` for the UCG. Where this file and the README disagree, the README wins.

Port `provisioner.py` and `sip_client.py` into a single Rust binary. Package in a distroless Docker container (`gcr.io/distroless/cc-debian12`). Target: `x86_64-unknown-linux-gnu`.

## Files to port

- **`provisioner.py`** — HTTPS client that talks to two ISP servers (CCS over IPv6, ACS over IPv4 with Digest auth + SOAP XML). Outputs SIP config as key=value pairs.
- **`sip_client.py`** — SIP client over TLS/IPv6. Registers, places calls with PRACK, relays RTP audio.

Read both files, understand the flow, then rewrite in Rust.

## Crates

| Purpose | Crate |
|---|---|
| Async runtime | `tokio` |
| TLS | `rustls` + `tokio-rustls` |
| HTTPS client | `reqwest` (rustls backend) |
| MD5 hashing | `md-5` |
| XML parsing | `quick-xml` |
| SIP parsing | `rsip` or hand-roll on tokio |
| AMR codec | FFI to `libopencore-amrnb` via `bindgen` |
| RTP | Hand-roll (12-byte header + payload) |

## Env vars

**Provisioner inputs** (always run — the rotating SIP password is never a static input):

- `DEVICE_SERIAL` (required), `TR069_PASSWORD` (required)
- `DEVICE_MODEL` (default `JCOW414`), `DEVICE_MSISDN` (discovered from ACS when unset)
- `DEVICE_TOKEN` (derived from serial), `DEVICE_SW_VER` (default `R2.57`)
- SIP config (`SIP_AUTH_USER`, realm, `PUBLIC_ID`, `REGISTRAR_HOST`, `PROXY_HOST`) comes from
  the provisioner output; `PROXY_HOST` port defaults to 5061

**ONT line takeover** (optional — telnet in to disable the ONT's own SIP):

- `ONT_HOST` (unset = skip), `ONT_TELNET_PASSWORD`, `ONT_TELNET_USER` (default `root`),
  `ONT_TELNET_PORT` (default 23)

**Local network:**

- `LOCAL_PORT` (5061), `RTP_PORT` (52000), `DEST_TO_LOCAL`

## Implementation order

1. `cargo init`
2. Port `provisioner.py`
3. Port SIP registration from `sip_client.py`
4. Port INVITE/PRACK flow
5. Add RTP relay with AMR↔PCMU transcoding
6. Add B2BUA bridge (local UDP SIP ↔ upstream TLS SIP)
7. Dockerfile
