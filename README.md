# JioFiber SIP Proxy

Use any standard SIP phone or PBX on your JioFiber landline, without the Jio-supplied
router handling voice. This single binary impersonates the JioFiber ONT (a Sercomm
JCOW414) to Jio's IMS core, registers as your line, and bridges calls to a plain SIP
device on your LAN — transcoding the audio for you.

> **This is an advanced, self-hosted setup.** It requires access to your JioFiber line's
> IPv6 network and your device's provisioning secrets. Read [Before you start](#before-you-start)
> to see whether you can gather what it needs.

---

## How it works

```
  Your SIP phone                 jiofiber-sip-proxy                 Jio IMS (VoLTE core)
  ──────────────                 ──────────────────                 ────────────────────
  SIP over UDP        ◄───────►   back-to-back UA    ◄──────────►   SIP over IPv6 + TLS
  audio: PCMU/G.711   ◄───────►   transcode audio    ◄──────────►   audio: AMR-NB
                                        │
                                   fetch + refresh
                                   credentials from Jio CCS/ACS
```

It runs in **two phases**:

1. **Provisioning** *(automatic)* — impersonates your ONT to Jio's CCS and ACS servers
   to fetch your SIP credentials, and refreshes them when they rotate.
2. **Bridge** — registers to IMS as your line and relays each call between your phone
   (SIP/UDP, G.711) and IMS (SIP/TLS over IPv6, AMR-NB), one active call at a time.

For a deeper walkthrough of the internals, see the source — `bridge.rs` (call state
machine), `upstream.rs` (IMS link + P-CSCF discovery), `provisioner.rs` (CCS/ACS),
`rtp.rs` (audio relay/transcode).

---

## Before you start

**You need a Linux host** (Docker recommended, or a native build) on the same network as
your JioFiber line, with a global **IPv6** address inside your subscriber's `/64` (the proxy
sources its IMS traffic from it) and **IPv4** reach to Jio's ACS.

**The easiest path: point it at your ONT.** Just set `ONT_HOST` — the proxy telnets into the
ONT at startup (trying the known default JioFiber login, so you usually need no password) and
reads everything it needs — the serial and the TR-069 password — straight off the device, even
when the ONT is bridged. It also disables the ONT's own SIP so it won't fight the proxy for the
line (see [Taking over the line](#taking-over-the-line)). In that mode you supply **nothing**
about the device. If your ONT's telnet password was changed, set `ONT_TELNET_PASSWORD` (and
`ONT_TELNET_USER` if it isn't the default).

**Or supply them by hand.** When you can't give the proxy telnet access (a non-Jio gateway,
telnet disabled), provide the two facts yourself; these always override what the ONT reports:

| Value | What it is | Where it comes from |
| --- | --- | --- |
| **Device serial** (`DEVICE_SERIAL`) | Your ONT's serial number | The sticker on the ONT |
| **TR-069 password** (`TR069_PASSWORD`) | The ONT's factory ACS/TR-069 password | [Get your TR-069 password](#get-your-tr-069-password) |

Either way: the device token is computed from the serial, your number (MSISDN) is fetched
from the ACS during provisioning, and the SIP password is **always** pulled from provisioning
(it rotates) — never a static env var.

**Prefer a UI?** Run the built-in setup wizard instead of hand-writing env vars — set
`ADMIN_BIND` and the proxy serves a step-by-step page that discovers from the ONT and applies
config live. See [Setup wizard](#setup-wizard).

---

## Taking over the line

IMS allows one registration per identity. If the JioFiber ONT keeps its own voice stack
running, both it and this proxy will register the line and knock each other offline. To hand
the line cleanly to the proxy, set `ONT_HOST` (the known default login is tried automatically;
override with `ONT_TELNET_USER`/`ONT_TELNET_PASSWORD`); at startup the proxy telnets into the
ONT and disables its voice two ways:

- **Persistently.** The ONT's root filesystem is a read-only squashfs, but its boot
  (`platformInit3`) runs a writable override `/flash2/pfrm2.0/etc/voipInit` *instead of* the
  stock one when it exists. The proxy installs an override there that sets up the voip status
  files but never launches `hgw-voice-app`. This survives reboots and is **fully reversible** —
  delete that file to restore the stock voice stack. Re-running is a no-op (idempotent).
- **Immediately.** `killall hgw-voice-app` drops any current registration without a reboot.

If `ONT_HOST` is unset the step is skipped entirely. A telnet failure is non-fatal: the proxy
logs a warning and keeps running (you can disable the ONT's voice by hand instead). This only
applies where the Jio ONT actually runs voice; if your line already terminates on this proxy
(e.g. the ONT is bridged), you can leave it unset.

## Setup wizard

Prefer clicking to editing env files? Set `ADMIN_BIND` (e.g. `127.0.0.1:8088`) and the proxy
serves a built-in setup wizard on that address. It walks you through the config step by step,
**finds your ONT by scanning the network** and **reads the serial and TR-069 password off it**
(so you type no address, serial, or password), reads your host's line `/64` so you pick the
right source address, and **applies changes live** — the proxy re-provisions and re-registers
in place, no restart.

- Bind it to **loopback** (the default guard) and reach it with an SSH tunnel, or bind to a
  LAN address **with `ADMIN_TOKEN` set** — it holds secrets, so a non-loopback bind without a
  token is refused. With a token, open `http://host:port/?token=<ADMIN_TOKEN>`.
- Applied config is written to `CONFIG_FILE` (default `/data/sip.env`); mount a volume there
  to keep it across container recreation. That file overrides the container's startup env.
- If the proxy starts with no working config, it stays up and waits for you to supply it
  through the wizard instead of exiting — so a first run with just `ADMIN_BIND` set is enough
  to configure everything from the browser.

The same page also works offline as a plain `sip.env` generator (it just hands you the file to
copy) when opened outside the proxy.

## Get your TR-069 password

The TR-069 password is a per-device, factory-random secret — it **can't** be computed from
your serial or MAC. Read it off your own ONT:

- **From a config backup (no shell needed).** In the ONT's web UI, download a settings backup
  (a `*.enc` file), then decrypt it with the model-static key:

  ```sh
  openssl aes-128-cbc -d -md sha256 \
    -pass pass:"BE F2 26 75 7C B1 49 CB 04 CD CA 84 DC 5B E9 55" \
    -in backup.enc -out config.txt
  grep -i ManagementServer.Password config.txt
  ```

  That passphrase is the JCOW414 model constant; other models use a different one.
- **From a root shell on the ONT**, if you have one: `cat /tmp/acs_passwd`.

Put the value in `TR069_PASSWORD`.

---

## Step 1 — Create your env file

Save this as `sip.env`. **Never commit it** — it holds secrets and PII (`.gitignore`
already excludes `*.env`). The device identity is **not** required here when the proxy can
read it off your ONT (set `ONT_HOST`); supply it by hand only when it can't.

```sh
# ── Device identity ───────────────────────────────────────────────
# Leave UNSET to have the proxy read them off the ONT over telnet (set
# ONT_HOST below). Supply by hand only when it can't — a non-Jio gateway,
# or telnet disabled. When set, these override what the ONT reports.
# DEVICE_SERIAL=RSV...
# TR069_PASSWORD=...
# DEVICE_MSISDN is always optional — discovered from the ACS when omitted:
# DEVICE_MSISDN=+9199XXXXXXXX

# ── ONT access (the easy path) ────────────────────────────────────
# Point at your ONT: the proxy reads the serial + TR-069 password off it
# and disables its own SIP. Don't know the address? Set ADMIN_BIND and let
# the setup wizard scan the LAN to find it. Leave ONT_HOST unset to skip.
ONT_HOST=192.168.0.51
# ONT_TELNET_PASSWORD=...   # only if the ONT's telnet password was changed

# ── Source addresses on your Jio line (host-side; always needed) ──
CCS_SOURCE_IPV6=2405:...:1
ACS_SOURCE_IPV4=192.168.0.4
SIP_SOURCE_IPV6=2405:...:1

# ── Local side (where your phone connects) ────────────────────────
LOCAL_BIND=0.0.0.0
LOCAL_ADVERTISE_IP=192.168.1.10
```

**Set `ONT_HOST` _or_ uncomment `DEVICE_SERIAL` + `TR069_PASSWORD` — you don't need both.**
Placeholders (`...`, `XXX`) stand in for your values; each variable's meaning is in the
[configuration reference](#configuration-reference). Keep comments on their own lines —
`docker --env-file` treats an inline `#` as part of the value.

---

## Step 2 — Run it

### Docker (recommended)

Build for your host's architecture, then run with your env file:

```sh
# amd64 — Intel/AMD hosts and most servers
docker build --platform linux/amd64 -t jiofiber-sip-proxy .

# arm64 — Raspberry Pi, ARM routers, Apple-silicon Linux
docker build --platform linux/arm64 -f Dockerfile.arm64 -t jiofiber-sip-proxy .

docker run --rm --network host --env-file ./sip.env jiofiber-sip-proxy
```

`--network host` is required so the container can source traffic from your line's real
IPv6/IPv4 addresses. Configure those source addresses on the host interface before
starting (see [Troubleshooting](#troubleshooting)).

### Native build

Install Rust, Clang/libclang, pkg-config, and the OpenCORE AMR-NB dev library
(`libopencore-amrnb-dev` + `libssl-dev` on Debian; `opencore-amr` via Homebrew). Then:

```sh
cargo build --release --locked
set -a; . ./sip.env; set +a          # load sip.env into the environment
./target/release/jiofiber-sip-proxy
```

On startup you should see:

```
Local SIP/UDP listening at 0.0.0.0:5061
Registered with upstream SIP proxy
```

That second line means you are attached to IMS and ready to take calls.

---

## Step 3 — Point your SIP phone at it

Configure the handset/PBX:

- **SIP server / outbound proxy:** the proxy's `LOCAL_ADVERTISE_IP` and `LOCAL_PORT`
  (default `5061`), transport **UDP**.
- **Codec:** **PCMU (G.711 µ-law)** first. The proxy speaks PCMU to the phone.
- **Registration:** the proxy answers any `REGISTER` with `200 OK`, so any username/
  password works on the phone side.

Dialing: ten-digit Indian numbers are automatically rewritten to `+91`. To receive
calls, set `DEST_TO_LOCAL` to your phone's SIP address (see the reference).

---

## Configuration reference

### Device identity & provisioning inputs

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DEVICE_SERIAL` | yes, or via ONT | — | ONT serial number (the device token is derived from it). Read from the ONT automatically when `ONT_HOST` is set; this env var overrides it |
| `TR069_PASSWORD` | yes, or via ONT | — | ONT's TR-069/ACS password ([how to get it](#get-your-tr-069-password)). Read from the ONT (`/tmp/acs_passwd`) automatically when `ONT_HOST` is set; this env var overrides it |
| `DEVICE_MSISDN` | no | discovered from ACS | Your line's number, full `+91…` form. Auto-discovered via a TR-069 bootstrap when unset; set it to skip that lookup |
| `DEVICE_TOKEN` | no | derived from serial | Overrides the derived device token / SIP instance id; normally leave unset |
| `DEVICE_MODEL` | no | `JCOW414` | Device model string |
| `DEVICE_SW_VER` | no | `R2.57` | Device software version string |
| `CCS_SOURCE_IPV6` | recommended | unspecified | Source IPv6 for CCS. Any address in your line's `/64` works |
| `ACS_SOURCE_IPV4` | recommended | unspecified | Source IPv4 for ACS |

### ONT access (optional, but the easy path)

Set `ONT_HOST` and the proxy telnets into the ONT to read the serial + TR-069 password and to
disable the ONT's own SIP (see [Taking over the line](#taking-over-the-line)). Leave it unset
to skip and configure by hand.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ONT_HOST` | no | — | ONT telnet address. When set, the proxy reads config from the ONT and disables its voice at startup |
| `ONT_TELNET_PASSWORD` | no | known default | Telnet password. Blank = try the published JioFiber default; set it only if yours was changed |
| `ONT_TELNET_USER` | no | `root` | Telnet login user. Blank = the known default (`root`). (The web-UI `superadmin` account only *enables* telnet; it is not a telnet login.) |
| `ONT_TELNET_PORT` | no | `23` | Telnet port |
| `ONT_DISABLE_VOICE` | no | `1` | Set `0` to read config from the ONT without disabling its voice |

### Setup wizard / admin UI (optional)

Set `ADMIN_BIND` and the proxy serves a step-by-step [setup wizard](#setup-wizard) that
discovers from the ONT and applies config live (no restart).

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ADMIN_BIND` | no | off | `host:port` to serve the wizard on, e.g. `127.0.0.1:8088`. Unset = no admin server |
| `ADMIN_TOKEN` | if non-loopback | — | Shared token guarding the UI. **Required** if `ADMIN_BIND` is not loopback; open `http://host:port/?token=…` |
| `CONFIG_FILE` | no | `/data/sip.env` | Where applied config is written and reloaded from. Mount a volume here to persist it across container recreation |

### Network and local side

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIP_SOURCE_IPV6` | unspecified | Source IPv6 for the IMS SIP/TLS link and IMS-side RTP |
| `LOCAL_BIND` | `127.0.0.1` | Bind address for the phone-facing SIP/UDP + RTP. Use a LAN IP or `0.0.0.0` when the phone is on another host |
| `LOCAL_ADVERTISE_IP` | = `LOCAL_BIND` | Address advertised to the phone in SIP/SDP. Set a concrete IP when `LOCAL_BIND` is a wildcard |
| `LOCAL_PORT` | `5061` | Phone-facing SIP/UDP port (also the upstream SIP/TLS source port) |
| `RTP_PORT` | `52000` | IMS-side RTP port (the phone leg gets an ephemeral port) |
| `DEST_TO_LOCAL` | — | Inbound call destination, e.g. `sip:1001@192.168.1.10:5060` or `192.168.1.10:5060`. Without it, the proxy is outbound-only |
| `TLS_INSECURE` | `0` | Set `1` to skip IMS TLS certificate validation (for private/self-signed ISP endpoints) |
| `SIP_DEBUG_REGISTER` | — | Set `1` to log outgoing `REGISTER` messages (includes identities and Digest auth) |

> The SIP instance id in the Contact is the device token — derived from `DEVICE_SERIAL`,
> or taken from `DEVICE_TOKEN` if you set it.

---

## Commands

```sh
jiofiber-sip-proxy            # (default) run the bridge
jiofiber-sip-proxy bridge     # same as above
jiofiber-sip-proxy provision  # run CCS + TR-069 and print the six SIP_* values, then exit
jiofiber-sip-proxy call NUMBER [WAV_PATH]  # place one diagnostic call, record the far end
```

`provision` runs the CCS/ACS exchange and prints the resolved `SIP_*` values, then exits —
a quick way to preview your credentials without starting the bridge:

```sh
set -a; . ./sip.env; set +a
jiofiber-sip-proxy provision
```

`call` places a test call (plays a melody, records incoming audio to an 8 kHz WAV,
default `/tmp/jio_recording.wav`) — a way to verify the IMS leg without a phone.

---

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `resolving SIP proxy … No address` | Old builds only did A/AAAA on the home domain. Current builds resolve it via NAPTR→SRV — rebuild |
| `CCS request failed … Connection reset by peer` | Either the wrong `DEVICE_MSISDN`, a source address **not** in your line's `/64`, or Jio throttling after rapid retries — wait and retry |
| Provisioning fails but the network looks right | Double-check `DEVICE_SERIAL` and `TR069_PASSWORD` |
| No audio, one-way audio, or codec errors | Set the phone to **PCMU** first; ensure `LOCAL_ADVERTISE_IP` is reachable from the phone and RTP isn't firewalled |
| IMS TLS handshake fails | Try `TLS_INSECURE=1` if your P-CSCF presents a private certificate |
| The phone registers but your ONT's line stops working | Expected: IMS allows one registration per identity. The proxy and the ONT share the same line, so whichever registers last wins. Run the proxy in exactly one place |

Configure your line's source addresses on the host before starting, e.g.:

```sh
ip -6 addr add 2405:...:1/64 dev <iface> nodad
```

---

## Third-party software

Dependency versions live in `Cargo.toml`, which is authoritative; this lists roles.
SIP, SDP, RTP, TR-069, and Digest are implemented in this repository, not from a library.

**System C library** — the only non-Rust component:

- **OpenCORE AMR-NB** (`libopencore-amrnb`) — the AMR-NB audio codec, linked over FFI
  with bindings generated at build time by `bindgen`. Ships as `libopencore-amrnb.so.0`.

**Rust crates (direct):** `tokio` (async runtime), `reqwest`+rustls (CCS/ACS HTTPS),
`native-tls`/`tokio-native-tls` (IMS SIP TLS — the P-CSCF needs a legacy OpenSSL cipher),
`hickory-resolver` (NAPTR→SRV→A/AAAA P-CSCF discovery), `quick-xml` (TR-069 SOAP + CCS
profile XML), `md-5` (Digest), `uuid`, `time`, `anyhow`. Build-time: `bindgen`, `pkg-config`.
Runtime image: `gcr.io/distroless/cc-debian12`.

---

## Security notes

- **Your `sip.env` holds secrets and PII** (serial, number, TR-069 password).
  Keep it out of git — `*.env` is already gitignored.
- SIP passwords rotate; the proxy re-fetches them automatically each run.
- Run the proxy in **one** place only — it registers as your line and will displace any
  other device (including the ONT) registered on the same identity.
