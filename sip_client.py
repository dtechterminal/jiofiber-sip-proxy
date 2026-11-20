#!/usr/bin/env python3
"""
jio_call.py — Place a call via JioFiber IMS with audio
Sends a test melody, records incoming audio.
"""
import os, socket, ssl, uuid, time, re, hashlib, subprocess, sys, struct, math, threading

# ── SIP credentials — supplied via environment, never hard-coded ─────────────
DOMAIN   = os.environ.get("SIP_REALM", "ue.wln.ims.jio.com")
IMPU     = os.environ["PUBLIC_ID"]                        # sip:+91…@<domain>
IMPI     = os.environ["SIP_AUTH_USER"]                    # 91…@<domain>
PASSWORD = os.environ["SIP_PASSWORD"]
PCSCF    = os.environ.get("PROXY_HOST", "pcscf.ue.wln.ims.jio.com")
INSTANCE = os.environ["DEVICE_TOKEN"]                     # <urn:uuid:…>, same token as provisioner
TARGET   = sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: sip_client.py <number>")
if not TARGET.startswith("+91"):
    TARGET = "+91" + TARGET.lstrip("+")
TARGET_URI = f"sip:{TARGET}@{DOMAIN}"

out = subprocess.run(["ip","-6","addr","show","eth4.1015"], capture_output=True, text=True).stdout
m = re.search(r"inet6 (2405:[0-9a-f:]+)/", out)
SRC = m.group(1)
import random as _rnd
LPORT    = 45060 + _rnd.randint(1, 999)
RTP_PORT = 49000 + _rnd.randint(0, 50) * 2
RECORD_FILE = "/tmp/jio_recording.raw"
WAV_FILE = "/tmp/jio_recording.wav"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════════════════════════
# μ-law codec (G.711)
# ═══════════════════════════════════════════════════════════════════════════════

def pcm_to_ulaw(sample):
    """16-bit signed PCM → 8-bit μ-law."""
    BIAS, CLIP = 0x84, 32635
    sign = 0x80 if sample < 0 else 0
    sample = min(abs(sample), CLIP) + BIAS
    exp = 7
    mask = 0x4000
    while exp > 0 and not (sample & mask):
        exp -= 1
        mask >>= 1
    mantissa = (sample >> (exp + 3)) & 0x0F
    return (~(sign | (exp << 4) | mantissa)) & 0xFF


def ulaw_to_pcm(ulaw_byte):
    """8-bit μ-law → 16-bit signed PCM."""
    ulaw_byte = ~ulaw_byte & 0xFF
    sign = ulaw_byte & 0x80
    exp = (ulaw_byte >> 4) & 0x07
    mantissa = ulaw_byte & 0x0F
    sample = (mantissa << (exp + 3)) + (0x84 << exp) - 0x84
    return -sample if sign else sample


def generate_tone(freq, duration_ms, volume=0.5):
    """Generate μ-law encoded tone. Returns bytes."""
    samples = int(8000 * duration_ms / 1000)
    result = bytearray(samples)
    for i in range(samples):
        t = i / 8000.0
        pcm = int(volume * 32000 * math.sin(2 * math.pi * freq * t))
        result[i] = pcm_to_ulaw(pcm)
    return bytes(result)


def generate_melody():
    """Generate a recognizable test melody in μ-law."""
    # "Twinkle twinkle" pattern: C C G G A A G - F F E E D D C
    notes = [
        (523, 300), (523, 300), (784, 300), (784, 300),
        (880, 300), (880, 300), (784, 600),
        (698, 300), (698, 300), (659, 300), (659, 300),
        (587, 300), (587, 300), (523, 600),
    ]
    audio = bytearray()
    for freq, ms in notes:
        audio.extend(generate_tone(freq, ms, 0.4))
        audio.extend(generate_tone(0, 20))  # tiny gap
    return bytes(audio)


# ═══════════════════════════════════════════════════════════════════════════════
# RTP
# ═══════════════════════════════════════════════════════════════════════════════

def make_rtp_packet(seq, ts, ssrc, payload_type, payload):
    hdr = struct.pack("!BBHII", 0x80, payload_type & 0x7F, seq, ts, ssrc)
    return hdr + payload


class RTPSession:
    def __init__(self, local_port, remote_addr, remote_port, payload_type=0):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind((SRC, local_port, 0, 0))
        self.sock.settimeout(0.05)
        self.remote = (remote_addr, remote_port, 0, 0)
        self.pt = payload_type
        self.ssrc = 0x12345678
        self.seq = 0
        self.ts = 0
        self.running = False
        self.recorded = bytearray()

    def send_audio(self, audio_data):
        """Send audio data as RTP packets (160 bytes = 20ms each for PCMU)."""
        pkt_size = 160
        for offset in range(0, len(audio_data), pkt_size):
            chunk = audio_data[offset:offset + pkt_size]
            if len(chunk) < pkt_size:
                chunk += bytes(pkt_size - len(chunk))
            pkt = make_rtp_packet(self.seq & 0xFFFF, self.ts, self.ssrc, self.pt, chunk)
            try:
                self.sock.sendto(pkt, self.remote)
            except Exception:
                pass
            self.seq += 1
            self.ts += pkt_size
            time.sleep(0.018)  # ~20ms pacing

    def recv_loop(self):
        """Receive RTP and store raw audio."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if len(data) > 12:
                    payload = data[12:]
                    self.recorded.extend(payload)
            except socket.timeout:
                continue

    def save_recording(self):
        """Save recorded μ-law audio as WAV."""
        if not self.recorded:
            log("No audio recorded")
            return
        # Convert μ-law to 16-bit PCM for WAV
        pcm = bytearray()
        for b in self.recorded:
            sample = ulaw_to_pcm(b)
            pcm.extend(struct.pack("<h", sample))

        # Write WAV header + data
        data_size = len(pcm)
        with open(WAV_FILE, "wb") as f:
            f.write(b"RIFF")
            f.write(struct.pack("<I", 36 + data_size))
            f.write(b"WAVE")
            f.write(b"fmt ")
            f.write(struct.pack("<I", 16))       # chunk size
            f.write(struct.pack("<H", 1))        # PCM format
            f.write(struct.pack("<H", 1))        # mono
            f.write(struct.pack("<I", 8000))     # sample rate
            f.write(struct.pack("<I", 16000))    # byte rate
            f.write(struct.pack("<H", 2))        # block align
            f.write(struct.pack("<H", 16))       # bits per sample
            f.write(b"data")
            f.write(struct.pack("<I", data_size))
            f.write(pcm)
        log(f"Recording saved: {WAV_FILE} ({len(self.recorded)} samples, {len(self.recorded)/8000:.1f}s)")

    def close(self):
        self.running = False
        self.sock.close()


# ═══════════════════════════════════════════════════════════════════════════════
# SDP parsing
# ═══════════════════════════════════════════════════════════════════════════════

def parse_sdp(text):
    """Extract remote RTP address, port, and codec from SDP in SIP response."""
    sdp_match = re.search(r"\r\n\r\n(v=0.*)", text, re.S)
    if not sdp_match:
        return None
    sdp = sdp_match.group(1)
    # Connection address
    c = re.search(r"c=IN IP6 ([^\r\n]+)", sdp) or re.search(r"c=IN IP4 ([^\r\n]+)", sdp)
    addr = c.group(1).strip() if c else None
    # Media port
    m = re.search(r"m=audio (\d+)", sdp)
    port = int(m.group(1)) if m else None
    # Payload types
    pt_match = re.search(r"m=audio \d+ RTP/AVP (.+?)[\r\n]", sdp)
    pts = pt_match.group(1).strip().split() if pt_match else []
    # Find PCMU/PCMA
    codec_pt = None
    for pt in pts:
        if pt == "0":
            codec_pt = 0  # PCMU
            break
        if pt == "8":
            codec_pt = 8  # PCMA
            break
    if codec_pt is None and pts:
        codec_pt = int(pts[0])  # use whatever they offered first
    return {"addr": addr, "port": port, "pt": codec_pt, "pts": pts}


# ═══════════════════════════════════════════════════════════════════════════════
# SIP (reused from previous version with minor tweaks)
# ═══════════════════════════════════════════════════════════════════════════════

def _branch():
    return f"z9hG4bK{uuid.uuid4().hex[:12]}"

call_id_reg = uuid.uuid4().hex[:16]
from_tag = uuid.uuid4().hex[:8]
call_id_inv = uuid.uuid4().hex[:16]
from_tag_inv = uuid.uuid4().hex[:8]

def _contact():
    return (f"<sip:{IMPI.split('@')[0]}@[{SRC}]:{LPORT};transport=tls>"
            f';+sip.instance="{INSTANCE}"'
            ';+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"')

def parse_401(resp):
    ch = {}
    for hdr_name in ("WWW-Authenticate", "Proxy-Authenticate"):
        m = re.search(rf"{hdr_name}:\s*Digest\s+(.+?)(?:\r\n(?!\s)|\r\n\r\n)", resp, re.S|re.I)
        if m:
            for m2 in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
                ch[m2.group(1)] = m2.group(2)
            for m2 in re.finditer(r'(\w+)=([^",\s]+)', m.group(1)):
                ch.setdefault(m2.group(1), m2.group(2))
            break
    return ch

def _digest(ch, method, uri):
    realm = ch.get("realm", DOMAIN)
    nonce = ch.get("nonce", "")
    qop = ch.get("qop", "")
    ha1 = hashlib.md5(f"{IMPI}:{realm}:{PASSWORD}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    nc, cn = "00000001", uuid.uuid4().hex[:16]
    if "auth" in qop:
        r = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cn}:auth:{ha2}".encode()).hexdigest()
        return (f'Digest username="{IMPI}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", qop=auth, nc={nc}, cnonce="{cn}", response="{r}", algorithm=MD5')
    r = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{IMPI}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{r}", algorithm=MD5')

def _preauth():
    ha1 = hashlib.md5(f"{IMPI}:{DOMAIN}:{PASSWORD}".encode()).hexdigest()
    ha2 = hashlib.md5(f"REGISTER:sip:{DOMAIN}".encode()).hexdigest()
    r = hashlib.md5(f"{ha1}:::{ha2}".encode()).hexdigest()
    return (f'Digest username="{IMPI}", realm="{DOMAIN}", nonce="", '
            f'uri="sip:{DOMAIN}", response="{r}", algorithm=MD5')

def _register(auth, cseq):
    return (
        f"REGISTER sip:{DOMAIN} SIP/2.0\r\n"
        f"Via: SIP/2.0/TLS [{SRC}]:{LPORT};branch={_branch()};rport\r\n"
        f"Max-Forwards: 70\r\nFrom: <{IMPU}>;tag={from_tag}\r\nTo: <{IMPU}>\r\n"
        f"Call-ID: {call_id_reg}\r\nCSeq: {cseq} REGISTER\r\nContact: {_contact()}\r\n"
        f"Authorization: {auth}\r\nExpires: 600000\r\n"
        f"P-Access-Network-Info: GPON\r\nSupported: path,outbound,gruu\r\n"
        f"Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,NOTIFY,REFER,MESSAGE,OPTIONS\r\n"
        f"User-Agent: JCOW414/JUICEJFV-1.3.31\r\nContent-Length: 0\r\n\r\n"
    )

def _invite(auth, cseq):
    sdp = (
        f"v=0\r\no=JioCall 1 1 IN IP6 {SRC}\r\ns=-\r\nc=IN IP6 {SRC}\r\nt=0 0\r\n"
        f"m=audio {RTP_PORT} RTP/AVP 0 8 118 101\r\n"
        f"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
        f"a=rtpmap:118 AMR/8000\r\na=fmtp:118 mode-set=7; octet-align=1\r\n"
        f"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n"
    )
    msg = (
        f"INVITE {TARGET_URI} SIP/2.0\r\n"
        f"Via: SIP/2.0/TLS [{SRC}]:{LPORT};branch={_branch()};rport\r\n"
        f"Max-Forwards: 70\r\nFrom: <{IMPU}>;tag={from_tag_inv}\r\nTo: <{TARGET_URI}>\r\n"
        f"Call-ID: {call_id_inv}\r\nCSeq: {cseq} INVITE\r\nContact: {_contact()}\r\n"
        f"P-Access-Network-Info: GPON\r\nP-Preferred-Identity: <{IMPU}>\r\n"
        f"Supported: 100rel,timer,precondition\r\n"
        f"Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,NOTIFY\r\n"
        f"User-Agent: JCOW414/JUICEJFV-1.3.31\r\nContent-Type: application/sdp\r\n"
    )
    if auth:
        msg += f"Proxy-Authorization: {auth}\r\n"
    msg += f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
    return msg

def _ack(resp, cseq):
    to_m = re.search(r"To:.*?;tag=([^\s;]+)", resp, re.I)
    to_tag = f";tag={to_m.group(1)}" if to_m else ""
    return (
        f"ACK {TARGET_URI} SIP/2.0\r\n"
        f"Via: SIP/2.0/TLS [{SRC}]:{LPORT};branch={_branch()};rport\r\n"
        f"Max-Forwards: 70\r\nFrom: <{IMPU}>;tag={from_tag_inv}\r\n"
        f"To: <{TARGET_URI}>{to_tag}\r\nCall-ID: {call_id_inv}\r\n"
        f"CSeq: {cseq} ACK\r\nContent-Length: 0\r\n\r\n"
    )

def _bye(resp):
    to_m = re.search(r"To:.*?;tag=([^\s;]+)", resp, re.I)
    to_tag = f";tag={to_m.group(1)}" if to_m else ""
    return (
        f"BYE {TARGET_URI} SIP/2.0\r\n"
        f"Via: SIP/2.0/TLS [{SRC}]:{LPORT};branch={_branch()};rport\r\n"
        f"Max-Forwards: 70\r\nFrom: <{IMPU}>;tag={from_tag_inv}\r\n"
        f"To: <{TARGET_URI}>{to_tag}\r\nCall-ID: {call_id_inv}\r\n"
        f"CSeq: 10 BYE\r\nContent-Length: 0\r\n\r\n"
    )

class Conn:
    def __init__(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        addrs = socket.getaddrinfo(PCSCF, 5061, socket.AF_INET6, socket.SOCK_STREAM)
        raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        raw.bind((SRC, LPORT, 0, 0))
        raw.settimeout(10)
        raw.connect(addrs[0][4])
        self.tls = ctx.wrap_socket(raw, server_hostname=PCSCF)
    def send(self, msg):
        self.tls.sendall(msg.encode())
    def recv(self, timeout=5):
        self.tls.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.tls.recv(65536)
                if not chunk: break
                data += chunk
                text = data.decode(errors="replace")
                if "\r\n\r\n" in text:
                    m = re.search(r"Content-Length:\s*(\d+)", text, re.I)
                    if m:
                        hend = text.index("\r\n\r\n") + 4
                        if len(text) >= hend + int(m.group(1)): break
                    elif "Content-Length" not in text: break
        except socket.timeout: pass
        return data.decode(errors="replace")
    def close(self):
        try: self.tls.close()
        except: pass


def get_st(r):
    m = re.search(r"SIP/2\.0 (\d+)", r)
    return int(m.group(1)) if m else 0


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    log(f"Calling {TARGET} from {IMPI}")
    log(f"Will play test melody and record your voice")

    melody = generate_melody()
    log(f"Melody: {len(melody)} samples ({len(melody)/8000:.1f}s)")

    conn = Conn()
    rtp = None
    last_resp = ""

    try:
        # ── REGISTER ──
        log("REGISTER...")
        conn.send(_register(_preauth(), 1))
        resp = conn.recv()
        if get_st(resp) == 401:
            ch = parse_401(resp)
            conn.send(_register(_digest(ch, "REGISTER", f"sip:{DOMAIN}"), 2))
            resp = conn.recv()
        if get_st(resp) != 200:
            log(f"Registration failed: {get_st(resp)}")
            return 1
        log("✓ Registered")

        # ── INVITE ──
        log(f"INVITE {TARGET}...")
        conn.send(_invite(None, 1))

        remote_sdp = None
        inv_cseq = 1

        answered = False
        for _ in range(30):
            resp = conn.recv(timeout=3)
            if not resp:
                continue
            last_resp = resp

            # May contain multiple SIP responses; find all status lines
            statuses = re.findall(r"SIP/2\.0 (\d+)[^\r\n]*", resp)
            for line in resp.split("\r\n"):
                if line.startswith("SIP/2.0"):
                    log(f"  {line.strip()}")

            # Use the LAST (most significant) status in this chunk
            st = int(statuses[-1]) if statuses else 0

            if st == 200:
                cseq_m = re.search(r"CSeq:\s*\d+\s+INVITE", resp)
                if cseq_m:
                    log("  ✓ ANSWERED!")
                    conn.send(_ack(resp, inv_cseq))
                    sdp = parse_sdp(resp)
                    if sdp and rtp:
                        rtp.remote = (sdp["addr"], sdp["port"], 0, 0)
                    answered = True

            if st == 407:
                ch = parse_401(resp)
                conn.send(_ack(resp, inv_cseq))
                inv_cseq += 1
                auth = _digest(ch, "INVITE", TARGET_URI)
                conn.send(_invite(auth, inv_cseq))
            elif st in (180, 183):
                sdp = parse_sdp(resp)
                if sdp and sdp["addr"] and sdp["port"] and not rtp:
                    pt = sdp["pt"] if sdp["pt"] is not None else 0
                    log(f"  Media: [{sdp['addr']}]:{sdp['port']} PT={pt}")
                    rtp = RTPSession(RTP_PORT, sdp["addr"], sdp["port"], pt)
                    rtp.running = True
                    threading.Thread(target=rtp.recv_loop, daemon=True).start()
                    log("  ♪ Sending melody (early media)...")
                    threading.Thread(target=rtp.send_audio, args=(melody,), daemon=True).start()
                # PRACK for reliable provisional
                rseq_m = re.search(r"RSeq:\s*(\d+)", resp, re.I)
                if rseq_m:
                    rseq = rseq_m.group(1)
                    # To header with tag from response
                    to_m = re.search(r"(?:^|\r\n)[Tt](?:o)?:\s*(.+?)(?:\r\n)", resp)
                    to_hdr = to_m.group(1).strip() if to_m else f"<{TARGET_URI}>"
                    # Contact from response (compact 'm:' or full 'Contact:')
                    ct_m = re.search(r"(?:^|\r\n)[Mm]:\s*<([^>]+)>", resp) or \
                           re.search(r"(?:^|\r\n)Contact:\s*<([^>]+)>", resp, re.I)
                    prack_uri = ct_m.group(1) if ct_m else TARGET_URI
                    # Route = Record-Route (same order for UAC sending within dialog)
                    rr = re.findall(r"Record-Route:\s*(<[^>]+>)", resp, re.I)
                    route_hdrs = "".join(f"Route: {r}\r\n" for r in rr)
                    inv_cseq += 1
                    prack = (
                        f"PRACK {prack_uri} SIP/2.0\r\n"
                        f"Via: SIP/2.0/TLS [{SRC}]:{LPORT};branch={_branch()};rport\r\n"
                        f"{route_hdrs}"
                        f"Max-Forwards: 70\r\n"
                        f"From: <{IMPU}>;tag={from_tag_inv}\r\n"
                        f"To: {to_hdr}\r\n"
                        f"Call-ID: {call_id_inv}\r\n"
                        f"CSeq: {inv_cseq} PRACK\r\n"
                        f"RAck: {rseq} 1 INVITE\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    )
                    conn.send(prack)
                    log(f"  PRACK RSeq={rseq} uri={prack_uri[:50]} route={len(rr)}")
            elif st >= 400:
                log(f"  Call failed ({st})")
                conn.send(_ack(resp, inv_cseq))

            if answered:
                break

        if answered:
            pass  # fall through to media handling
        elif rtp:
            log("  Call not answered but had early media")

        if rtp:
            # Play melody
            log("♪ Playing test melody...")
            rtp.send_audio(melody)
            log("♪ Melody done. Recording your voice for 15s...")
            time.sleep(15)
            # Play melody again
            log("♪ Playing melody again...")
            rtp.send_audio(melody)
            time.sleep(2)

            # Hang up
            log("Hanging up...")
            conn.send(_bye(last_resp))
            time.sleep(1)

            rtp.running = False
            rtp.save_recording()
            rtp.close()
        else:
            log("No RTP session established (no SDP in response)")

    except KeyboardInterrupt:
        log("Interrupted")
        if rtp:
            rtp.running = False
            rtp.save_recording()
            rtp.close()
        conn.send(_bye(last_resp))
    finally:
        conn.close()

    return 0

if __name__ == "__main__":
    sys.exit(main())
