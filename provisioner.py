#!/usr/bin/env python3
"""
jio_sip_fetch.py — JioFiber SIP Credential Extractor
Runs entirely on UCG (192.168.0.1) via eth4.1015 (Jio VLAN 1015).
Impersonates JCOW414 for TR-069 (ACS) and CCS (auto-config).

Flow:
  1. Add device's IPv6 to br0 (CCS validates source address)
  2. CCS trigger → get session cookie (queues OTP)
  3. TR-069 Inform to ACS → receive VerificationCode via SetParameterValues
  4. CCS fetch with OTP= param + same cookie → SIP profile XML
  5. Parse and output credentials
"""

import subprocess, re, sys, time, os, base64, hashlib, ssl, socket
from urllib.parse import quote

# ── Identity (JCOW414) — supplied via environment, never hard-coded ──────────
SERIAL     = os.environ["DEVICE_SERIAL"]                  # the ONT serial number
MODEL      = os.environ.get("DEVICE_MODEL", "JCOW414")
SW_VER     = os.environ.get("DEVICE_SW_VER", "R2.57")
MSISDN     = os.environ["DEVICE_MSISDN"]                  # full +91… subscriber number
RJIL_TOKEN = os.environ["DEVICE_TOKEN"]                   # <urn:uuid:…> = md5(SERIAL) as a UUID
DEVICE_IP6 = os.environ["CCS_SOURCE_IPV6"]               # any global IPv6 in the line's /64

# ── Endpoints ────────────────────────────────────────────────────────────────
CCS_HOST = "ue.wln.ccs.jio.com"
ACS_IP   = "49.40.134.113"
ACS_HOST = "acs.oss.jio.com"
ACS_PORT = 8443
ACS_PATH = "/ftacs-digest/ACS"
IFACE    = "eth4.1015"

# ── TR-069 auth ──────────────────────────────────────────────────────────────
TR069_USER = SERIAL
TR069_PASS = os.environ["TR069_PASSWORD"]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Network helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _src_ip4():
    out = subprocess.run(["ip", "-4", "addr", "show", IFACE],
                         capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def _raw_post(host, port, path, body, headers, src_ip=None, timeout=15):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if src_ip:
        sock.bind((src_ip, 0))
    sock.settimeout(timeout)
    sock.connect((host, port))
    tls = ctx.wrap_socket(sock, server_hostname=ACS_HOST)
    req = f"POST {path} HTTP/1.1\r\n"
    headers["Host"] = f"{ACS_HOST}:{port}"
    headers.setdefault("Content-Length", str(len(body.encode())))
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    tls.sendall(req.encode() + body.encode())
    resp = b""
    while True:
        try:
            chunk = tls.recv(65536)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                he = resp.index(b"\r\n\r\n") + 4
                hp = resp[:he]
                cl = re.search(rb"Content-Length:\s*(\d+)", hp, re.I)
                if cl and len(resp) >= he + int(cl.group(1)):
                    break
                if b"Content-Length: 0" in hp or (not cl and b"Transfer-Encoding" not in hp):
                    break
        except socket.timeout:
            break
    tls.close()
    text = resp.decode(errors="replace")
    parts = text.split("\r\n\r\n", 1)
    hdr = parts[0] if parts else ""
    bod = parts[1] if len(parts) > 1 else ""
    m = re.search(r"HTTP/\S+\s+(\d+)", hdr)
    return (int(m.group(1)) if m else 0), hdr, bod


# ═══════════════════════════════════════════════════════════════════════════════
# Digest auth
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_challenge(hdr):
    for line in hdr.split("\r\n"):
        if line.lower().startswith("www-authenticate"):
            raw = line.split(":", 1)[1].strip()
            d = {}
            for m in re.finditer(r'(\w+)="([^"]*)"', raw):
                d[m.group(1)] = m.group(2)
            for m in re.finditer(r'(\w+)=([^",\s]+)', raw):
                d.setdefault(m.group(1), m.group(2))
            return d
    return {}


def _digest_hdr(ch, user, password):
    realm, nonce, qop = ch.get("realm", ""), ch.get("nonce", ""), ch.get("qop", "")
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"POST:{ACS_PATH}".encode()).hexdigest()
    if "auth" in qop:
        nc, cn = "00000001", hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cn}:auth:{ha2}".encode()).hexdigest()
        h = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
             f'uri="{ACS_PATH}", qop=auth, nc={nc}, cnonce="{cn}", response="{resp}"')
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        h = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
             f'uri="{ACS_PATH}", response="{resp}"')
    if "opaque" in ch:
        h += f', opaque="{ch["opaque"]}"'
    return h


# ═══════════════════════════════════════════════════════════════════════════════
# TR-069 ACS client
# ═══════════════════════════════════════════════════════════════════════════════

_cookies = ""

def _acs(body):
    global _cookies
    src = _src_ip4()
    hdrs = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
    if _cookies:
        hdrs["Cookie"] = _cookies
    st, hdr, rb = _raw_post(ACS_IP, ACS_PORT, ACS_PATH, body, dict(hdrs), src)
    for m in re.finditer(r"Set-Cookie:\s*([^;\r\n]+)", hdr, re.I):
        _cookies = m.group(1)
    if st == 401:
        ch = _parse_challenge(hdr)
        hdrs["Authorization"] = _digest_hdr(ch, TR069_USER, TR069_PASS)
        if _cookies:
            hdrs["Cookie"] = _cookies
        st, hdr, rb = _raw_post(ACS_IP, ACS_PORT, ACS_PATH, body, dict(hdrs), src)
        for m in re.finditer(r"Set-Cookie:\s*([^;\r\n]+)", hdr, re.I):
            _cookies = m.group(1)
    return st, rb


NS = "http://schemas.xmlsoap.org/soap/envelope/"

def _inform():
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return f"""<?xml version="1.0"?>
<S:Envelope xmlns:S="{NS}" xmlns:E="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:C="urn:dslforum-org:cwmp-1-0" xmlns:I="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:D="http://www.w3.org/2001/XMLSchema">
<S:Header><C:ID S:mustUnderstand="1">1</C:ID></S:Header>
<S:Body><C:Inform>
 <DeviceId><Manufacturer>Sercomm</Manufacturer><OUI>001D68</OUI>
  <ProductClass>{MODEL}</ProductClass><SerialNumber>{SERIAL}</SerialNumber></DeviceId>
 <Event E:arrayType="C:EventStruct[1]">
  <EventStruct><EventCode>1 BOOT</EventCode><CommandKey/></EventStruct></Event>
 <MaxEnvelopes>1</MaxEnvelopes><CurrentTime>{ts}</CurrentTime><RetryCount>0</RetryCount>
 <ParameterList E:arrayType="C:ParameterValueStruct[2]">
  <ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name>
   <Value I:type="D:string">{SW_VER}</Value></ParameterValueStruct>
  <ParameterValueStruct><Name>Device.ManagementServer.ConnectionRequestURL</Name>
   <Value I:type="D:string">http://192.168.0.51:7547/</Value></ParameterValueStruct>
 </ParameterList>
</C:Inform></S:Body></S:Envelope>"""


def _spv_resp(cid):
    return f"""<?xml version="1.0"?>
<S:Envelope xmlns:S="{NS}" xmlns:C="urn:dslforum-org:cwmp-1-0">
<S:Header><C:ID S:mustUnderstand="1">{cid}</C:ID></S:Header>
<S:Body><C:SetParameterValuesResponse><Status>0</Status></C:SetParameterValuesResponse>
</S:Body></S:Envelope>"""


def _gpv_resp(cid, name, val):
    return f"""<?xml version="1.0"?>
<S:Envelope xmlns:S="{NS}" xmlns:E="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:C="urn:dslforum-org:cwmp-1-0" xmlns:I="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:D="http://www.w3.org/2001/XMLSchema">
<S:Header><C:ID S:mustUnderstand="1">{cid}</C:ID></S:Header>
<S:Body><C:GetParameterValuesResponse>
<ParameterList E:arrayType="C:ParameterValueStruct[1]">
 <ParameterValueStruct><Name>{name}</Name>
  <Value I:type="D:string">{val}</Value></ParameterValueStruct>
</ParameterList></C:GetParameterValuesResponse></S:Body></S:Envelope>"""


def tr069_session():
    global _cookies
    _cookies = ""
    st, _ = _acs(_inform())
    log(f"  Inform → {st}")
    if st != 200:
        return None
    vc = None
    for _ in range(10):
        st, body = _acs("")
        log(f"  → {st}, {len(body)}B")
        if st == 204 or not body:
            break
        cid = re.search(r"<C[^:]*:ID[^>]*>([^<]+)", body)
        cid = cid.group(1) if cid else "1"
        if "SetParameterValues" in body:
            m = re.search(r"VerificationCode.*?<Value[^>]*>([^<]*)", body, re.S)
            if m and m.group(1).strip():
                vc = m.group(1).strip()
                log(f"  ★ OTP = {vc}")
            _acs(_spv_resp(cid))
        elif "GetParameterValues" in body:
            nm = re.search(r"<string>([^<]+)</string>", body)
            nm = nm.group(1) if nm else ""
            _acs(_gpv_resp(cid, nm, vc if vc and "Verif" in nm else ""))
        else:
            _acs("")
    return vc


# ═══════════════════════════════════════════════════════════════════════════════
# CCS (IPv6, sourced from device address)
# ═══════════════════════════════════════════════════════════════════════════════

def ccs(otp="", cookie=None, vers=0):
    params = (
        f"rjil_token={quote(RJIL_TOKEN)}&serialNumber={SERIAL}"
        f"&terminal_model={MODEL}&terminal_sw_version={SW_VER}"
        f"&msisdn={quote(MSISDN)}&terminal_vendor=FX"
        f"&client_version=HGWVoice-3.0&SMS_port=0&rcs_version=5.1B"
        f"&client_vendor=WITS&rcs_profile=joyn_blackbird"
        f"&sim_mode=2&vers={vers}&token=&sub_version=0"
    )
    if otp:
        params += f"&OTP={quote(otp)}"
    cmd = ["curl", "-6", "-sSk", "--connect-timeout", "5", "-m", "15",
           "--interface", DEVICE_IP6, "-A", "JCOW414/JUICEJFV-1.3.31",
           "-D", "/tmp/_ch.txt", "-o", "/tmp/_cb.txt"]
    if cookie:
        cmd += ["-b", cookie]
    cmd.append(f"https://{CCS_HOST}/?{params}")
    subprocess.run(cmd, capture_output=True, timeout=20)
    hdr = open("/tmp/_ch.txt", errors="replace").read() if os.path.exists("/tmp/_ch.txt") else ""
    body = open("/tmp/_cb.txt", errors="replace").read() if os.path.exists("/tmp/_cb.txt") else ""
    m = re.search(r"HTTP/\S+\s+(\d+)", hdr)
    st = int(m.group(1)) if m else 0
    m = re.search(r"WITRCSeConfigCookie=([^;\s]+)", hdr)
    ck = m.group(1) if m else None
    return st, body, ck


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print(" JioFiber SIP Credential Extractor")
    print("=" * 60)

    # Add device IPv6 to br0
    subprocess.run(["ip", "-6", "addr", "add", f"{DEVICE_IP6}/64", "dev", "br0", "nodad"],
                   capture_output=True)

    try:
        for attempt in range(3):
            log(f"Attempt {attempt+1}")

            # 1. CCS trigger
            st, _, ck = ccs()
            cookie = f"WITRCSeConfigCookie={ck}" if ck else None
            log(f"  CCS trigger → {st}, cookie={ck}")
            if not ck:
                time.sleep(2)
                continue

            # 2. TR-069 → OTP
            otp = tr069_session()
            if not otp:
                log("  No OTP from ACS")
                time.sleep(3)
                continue

            # 3. CCS with OTP
            time.sleep(1)
            st, body, _ = ccs(otp=otp, cookie=cookie)
            log(f"  CCS fetch → {st}, {len(body)}B")

            if body and len(body) > 200:
                with open("/tmp/jio_sip_profile.xml", "w") as f:
                    f.write(body)
                creds = {}
                for m in re.finditer(r'parm\s+name="([^"]+)"\s+value="([^"]*)"', body):
                    creds[m.group(1)] = m.group(2)
                print("\n" + "=" * 60)
                print(" SIP CREDENTIALS")
                print("=" * 60)
                keys = ["Private_User_Identity", "Public_User_Identity",
                        "Home_network_domain_name", "AuthType", "Realm",
                        "UserName", "UserPwd", "Address", "AddressType",
                        "token", "version", "validity"]
                for k in keys:
                    if k in creds:
                        print(f"  {k}: {creds[k]}")
                print(f"\n  Full profile: /tmp/jio_sip_profile.xml")
                return 0

            time.sleep(3)

        log("FAILED after 3 attempts")
        return 1

    finally:
        subprocess.run(["ip", "-6", "addr", "del", f"{DEVICE_IP6}/64", "dev", "br0"],
                       capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
