# -*- coding: utf-8 -*-
"""Bunker Cleaner & Canonicalizer Engine.
Adapted and optimized for Bunker-Auto-Engine & BunkerVPN.
Implements Xray-core 26 compatibility, deep URI repairing,
canonical normalization, honeypot/junk filtering, and Blake2b fingerprinting.

Credits & Acknowledgments:
Special thanks to Nikita (https://t.me/urlsources / RKPchannel) for Xray 26 sanitization
logic, ML-KEM-768 validation, and exception hosting lists.
"""

import base64
import hashlib
import ipaddress
import json
import re
import socket
import struct
import urllib.parse
from urllib.parse import unquote, quote
import uuid as uuidlib

# Protocol registries
ACCEPTED = {"vless", "vmess", "ss", "trojan", "hysteria2"}
SCHEME_ALIAS = {"hy2": "hysteria2", "shadowsocks": "ss"}

# Modern Xray-core 26 supported networks (http, h2, quic were removed in Xray 26)
NETS = {"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
REMOVED_NETS = {"http", "h2", "h2c", "quic"}
KCP_HT = {"none", "srtp", "utp", "wechat", "dtls", "wireguard"}

# VMess ciphers accepted by Xray-core
VMESS_SCY = {"auto", "aes-128-gcm", "chacha20-poly1305", "none"}

# Shadowsocks methods supported by Xray-core 26 (AEAD & SS-2022)
SS_AEAD = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"}
SS_AEAD_ALIAS = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305"
}
SS_2022 = {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
SS_METHODS = SS_AEAD | SS_2022

SS_DEAD = {
    "none", "plain",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "rc4-md5-6", "chacha20-ietf", "chacha20", "xchacha20",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
    "seed-cfb", "table",
}
SS2022_KEYLEN = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32
}

TRUE_SET = {"1", "true", "yes", "on"}
FALSE_SET = {"0", "false", "no", "off"}
UTLS_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "unsafe"}
DEFAULT_FP = "firefox"

SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@")
RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
SNI_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._\-]*[A-Za-z0-9_])?$")

KNOWN_COMMON = {
    "encryption", "flow", "security", "sec", "sni", "peer", "servername", "host",
    "path", "p", "type", "network", "net", "fp", "fingerprint", "alpn", "pbk",
    "publickey", "sid", "shortid", "spx", "spiderx", "ech", "echconfiglist",
    "echconfig", "allowinsecure", "allowlnsecure", "insecure", "skip-cert-verify",
    "allow_insecure", "servicename", "service", "mode", "headertype", "header",
    "obfs", "seed", "ed", "max-early-data", "maxearlydata", "eh",
    "earlydataheadername", "early-data-header-name", "authority", "extra", "qsec",
    "quicsecurity", "key", "packetencoding", "packet-encoding", "pktenc",
    "grpc-service-name", "fm", "tfo", "tcp-fast-open", "tcp_fast_open",
    "fastopen", "mux", "ws", "wspath",
    "pinsha256", "pinnedpeercertsha256", "pin-sha256",
}
HY2_KNOWN = {
    "sni", "peer", "insecure", "allowinsecure", "allowlnsecure",
    "skip-cert-verify", "obfs", "obfs-password", "obfspassword",
    "obfs-param", "obfsparam", "pinsha256", "pin-sha256", "mport", "ports",
    "alpn", "fp", "fingerprint", "upmbps", "downmbps", "up-mbps",
    "down-mbps", "up", "down", "hop_interval", "hopinterval",
    "hop-interval", "fastopen", "fm",
    "obfs-min-packet-size", "obfs-max-packet-size",
    "obfsminpacketsize", "obfsmaxpacketsize"
}

# Canonical order of query parameters
PARAM_ORDER = {
    "ss": ("plugin",),
    "vless": (
        "encryption", "flow", "security", "sni", "alpn", "fp",
        "pbk", "sid", "spx", "allowInsecure", "insecure", "type",
        "headerType", "host", "path", "ed", "eh", "serviceName",
        "grpc-service-name", "mode", "seed", "extra",
        "packetEncoding", "pinsha256", "ech"
    ),
    "hysteria2": (
        "insecure", "obfs", "obfs-password", "pinSHA256",
        "sni", "fp", "alpn", "mport", "upmbps", "downmbps",
        "hop_interval", "obfs-min-packet-size",
        "obfs-max-packet-size"
    ),
}
PARAM_ORDER["trojan"] = PARAM_ORDER["vless"]

VMESS_JSON_ORDER = (
    "v", "ps", "add", "port", "id", "aid", "scy", "net",
    "type", "host", "path", "tls", "sni", "alpn", "fp",
    "pbk", "sid", "spx", "mode", "seed", "pinSHA256",
    "allowInsecure", "insecure"
)

# Bad IP networks & honeypots
BAD_V4 = [ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"
)]
BAD_V6 = [ipaddress.ip_network(x) for x in (
    "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32"
)]
IP_BLACKLIST = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"
}

JUNK_PASSWORDS = {"password", "yourpassword", "sspw"}
PLACEHOLDER_IPS = {"1.2.3.4"}
MIN_PORT = 22
MAX_PORT = 65535


class RejectConfig(Exception):
    """Raised when config is rejected due to invalid syntax, honeypot, or unsupported cipher."""
    pass


def b64d(s: str) -> bytes | None:
    if not s:
        return None
    s = re.sub(r"\s+", "", s).rstrip("=")
    for c in (s, s.replace("-", "+").replace("_", "/")):
        try:
            return base64.b64decode(c + "=" * ((-len(c)) % 4), validate=True)
        except Exception:
            continue
    return None


def preprocess(s: str) -> str:
    """Pre-cleans corrupted links: URL-encoded ampersands, unicode escapes, zero-width chars."""
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r"(?i)%5cu([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r"&amp;", "&", s, flags=re.I)
    if "¬" in s:
        s = s.replace("¬", "&")
    return s.replace("\u200b", "").strip()


def strip_fragment(body: str) -> str:
    i = body.find("#")
    return body[:i] if i >= 0 else body


def parse_query(qs: str) -> dict:
    q = {}
    for part in qs.split("&"):
        if not part:
            continue
        part = part.lstrip(";")
        if "=" not in part:
            try:
                dec = unquote(part)
            except Exception:
                dec = part
            if "=" in dec:
                part = dec
        k, _, v = part.partition("=")
        try:
            k, v = unquote(k).strip().lower(), unquote(v)
        except Exception:
            continue
        if k and k not in q:
            q[k] = v
    return q


def _q(q: dict, *names, default: str = "") -> str:
    for n in names:
        v = q.get(n.lower())
        if v not in (None, ""):
            return str(v)
    return default


def as_bool(v: str) -> bool:
    if not v:
        return False
    v = v.lower()
    return v in TRUE_SET


def trim_enum(v: str) -> str:
    m = re.match(r"[a-z0-9\-]+", v)
    return m.group(0) if m else ""


def valid_sni(s: str) -> bool:
    return bool(s) and len(s) <= 253 and bool(SNI_RE.fullmatch(s))


def norm_alpn(raw: str) -> list[str]:
    if not raw:
        return []
    r = raw
    for _ in range(3):
        if "%" not in r:
            break
        u = unquote(r)
        if u == r:
            break
        r = u
    amap = {
        "http1.1": "http/1.1", "h1": "http/1.1",
        "http2": "h2", "http/2": "h2",
        "http3": "h3", "http/3": "h3"
    }
    out = []
    for a in re.split(r"[,\s;]+", r):
        a = a.strip().lower()
        if not a:
            continue
        a = amap.get(a, a)
        if a in ("http/1.1", "h2", "h3") and a not in out:
            out.append(a)
    return out


def check_host(raw: str, reject_private: bool = True, reject_dns: bool = True) -> str:
    h = (raw or "").strip()
    if not h:
        raise RejectConfig("Empty host")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    
    # IPv6
    if ":" in h:
        try:
            ip = ipaddress.IPv6Address(h)
        except ValueError:
            raise RejectConfig(f"Invalid IPv6: {raw}")
        s = str(ip)
        if reject_dns and s in IP_BLACKLIST:
            raise RejectConfig(f"Blacklisted DNS IPv6: {s}")
        if reject_private:
            for net in BAD_V6:
                if ip in net:
                    raise RejectConfig(f"Private/reserved IPv6 {ip}")
        return s

    # IPv4
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h):
        if any(len(o) > 1 and o[0] == "0" for o in h.split(".")):
            raise RejectConfig("Obfuscated IP with leading zero")
        try:
            ip = ipaddress.IPv4Address(h)
        except ValueError:
            raise RejectConfig(f"Invalid IPv4: {h}")
        s = str(ip)
        if reject_dns and s in IP_BLACKLIST:
            raise RejectConfig(f"Blacklisted DNS IPv4: {s}")
        if reject_private:
            for net in BAD_V4:
                if ip in net:
                    raise RejectConfig(f"Private/reserved IPv4 {ip}")
        if s in PLACEHOLDER_IPS:
            raise RejectConfig(f"Placeholder doc IP: {s}")
        return s

    if re.fullmatch(r"[0-9.]+", h) or re.fullmatch(r"0[xX][0-9a-fA-F.]+", h):
        raise RejectConfig("Obfuscated numeric IP")

    # Domain name
    d = h.rstrip(".").lower()
    if not d or len(d) > 253 or "." not in d:
        raise RejectConfig(f"Invalid domain: {raw}")
    label = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
    parts = d.split(".")
    for p in parts:
        if not label.match(p):
            raise RejectConfig(f"Invalid domain label in {raw}")
    if len(parts[-1]) < 2 or parts[-1].isdigit():
        raise RejectConfig(f"Invalid domain TLD in {raw}")
    return d


def parse_hostport(s: str) -> tuple[str, int]:
    s = s.strip().strip("/")
    if not s:
        raise RejectConfig("Empty hostport")
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if not m:
            raise RejectConfig(f"Malformed IPv6 authority: {s}")
        host, port = m.group(1), m.group(2)
    else:
        host, sep, port = s.rpartition(":")
        if not sep or not port.isdigit():
            raise RejectConfig(f"No port specified in {s}")
    p = int(port)
    if not (MIN_PORT <= p <= MAX_PORT):
        raise RejectConfig(f"Port outside allowed range: {p}")
    return check_host(host), p


def _enc(v) -> str:
    return quote(str(v), safe="")


def fh(h: str) -> str:
    try:
        if ipaddress.ip_address(h).version == 6:
            return f"[{h}]"
    except ValueError:
        pass
    return h


class Node:
    """Normalized parsed proxy node."""
    __slots__ = (
        "proto", "host", "port", "uuid", "password", "method", "scy", "aid",
        "venc", "net", "sec", "flow", "sni", "hhost", "alpn", "fp",
        "insecure", "pbk", "sid", "spx", "ech", "path", "service", "mode",
        "htype", "seed", "qsec", "qkey", "ed", "eh", "authority", "plugin",
        "obfs", "obfsp", "pins", "mport", "upm", "dnm", "hop", "pkte",
        "gmin", "gmax", "extra", "remark", "notes"
    )

    def __init__(self, proto: str):
        self.proto = proto
        self.host, self.port = "", 0
        self.uuid = self.password = self.method = self.venc = ""
        self.scy, self.aid = "auto", 0
        self.net, self.sec, self.flow = "tcp", "none", ""
        self.sni = self.hhost = ""
        self.alpn, self.fp, self.insecure = [], "", False
        self.pbk = self.sid = self.spx = self.ech = ""
        self.path = self.service = self.mode = self.htype = ""
        self.seed = self.qsec = self.qkey = ""
        self.ed, self.eh, self.authority = None, "", ""
        self.plugin = self.obfs = self.obfsp = ""
        self.pins, self.mport, self.pkte, self.extra = [], "", "", ""
        self.upm = self.dnm = self.hop = ""
        self.gmin = self.gmax = ""
        self.remark = ""
        self.notes = []


def fix_wslike_path(p: str, n: Node) -> str:
    i = p.find("#")
    if i >= 0:
        p = p[:i] or "/"
    if not p.lower().startswith("/socks5://"):
        m = re.search(r"https?://|t\.me/", p, re.I)
        if m:
            p = p[:m.start()].rstrip("&?=@") or "/"
    if "://" in p.lower() and not p.lower().startswith("/socks5://"):
        raise RejectConfig(f"path contains full URI: {p[:40]}")
    if not p.startswith("/"):
        p = "/" + p
    return p or "/"


def _extract_ed_from_path(p: str, n: Node) -> str:
    m = re.search(r"[?&]ed=(\d+)", p)
    if not m:
        return p
    n.ed = int(m.group(1))
    p = re.sub(r"[?&]ed=\d+", "", p)
    if "?" not in p and "&" in p:
        p = p.replace("&", "?", 1)
    return p


def _salvage_glued_path(p: str, q: dict, n: Node) -> str:
    body = p[1:] if p.startswith("/") else p
    if not body or "=" not in body or "/" in body:
        return p
    parts = [x for x in re.split(r"[&;]", body) if x]
    if not parts:
        return p
    for part in parts:
        k, sep, _v = part.partition("=")
        if not sep or k.lower() not in KNOWN_COMMON:
            return p
    for k, v in parse_query(body.replace(";", "&")).items():
        if not _q(q, k):
            q[k] = v
    return "/"


def _split_query(body: str) -> tuple[str, dict]:
    q = {}
    if "?" in body:
        body, qs = body.split("?", 1)
        q = parse_query(qs)
    return body, q


def fill_transport(n: Node, q: dict, sec_default: str = "none"):
    for _pk in ("path", "p"):
        if _pk in q:
            q[_pk] = _salvage_glued_path(_extract_ed_from_path(q[_pk], n), q, n)
    
    net = _q(q, "type", "network", "net", default="").strip().lower()
    ob = _q(q, "obfs").strip().lower()
    if not net and ob:
        if ob in ("websocket", "ws"):
            net = "ws"
        elif ob == "http":
            net = "tcp"
    net = {"h2": "http", "h2c": "http", "websocket": "ws", "splithttp": "xhttp"}.get(net, net)
    if net in ("raw", "none", ""):
        net = "tcp"
    if net in REMOVED_NETS:
        raise RejectConfig(f"Transport '{net}' removed in Xray 26 (use xhttp)")
    if net not in NETS:
        t = trim_enum(net)
        if t in NETS:
            net = t
        else:
            raise RejectConfig(f"Unknown transport type={net}")
    n.net = net

    sec = _q(q, "security", "sec").strip().lower() or sec_default
    sec = trim_enum(sec) or sec_default
    if sec in ("false", "0", "auto", "off", "no"):
        sec = "none"
    if sec == "xtls":
        sec = "reality" if _q(q, "pbk", "publickey") else "tls"
    if sec not in ("none", "tls", "reality"):
        raise RejectConfig(f"Unknown security={sec}")
    n.sec = sec

    n.hhost = _q(q, "host").strip()
    sni = _q(q, "sni", "peer", "servername").strip()
    if sni and not valid_sni(sni):
        sni = ""
    if sec in ("tls", "reality"):
        n.sni = sni or n.hhost or n.host

    n.alpn = norm_alpn(_q(q, "alpn"))
    
    fp_raw = _q(q, "fp", "fingerprint").strip().lower()
    if fp_raw in UTLS_FP:
        n.fp = fp_raw
    elif fp_raw:
        n.fp = DEFAULT_FP
    else:
        if sec == "reality":
            n.fp = DEFAULT_FP

    # allowInsecure is sanitized
    n.insecure = as_bool(_q(q, "allowinsecure", "allowlnsecure", "insecure", "skip-cert-verify", "allow_insecure"))
    
    # Reality validation
    pbk = _q(q, "pbk", "publickey").strip()
    sid = _q(q, "sid", "shortid").strip()
    spx = _q(q, "spx", "spiderx").strip()
    if sec == "reality":
        n.insecure = False
        if not pbk:
            n.sec = "tls"
        else:
            if net not in ("tcp", "xhttp", "grpc"):
                raise RejectConfig(f"Reality requires tcp, xhttp, or grpc (got {net})")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", pbk.rstrip("=")):
                raise RejectConfig("Reality pbk is not 43-char base64url X25519")
            try:
                pbk_raw = base64.b64decode(pbk.rstrip("=") + "=", altchars=b"-_", validate=True)
            except Exception:
                pbk_raw = b""
            if len(pbk_raw) != 32 or not any(pbk_raw):
                raise RejectConfig("Reality pbk is empty or invalid key")
            n.pbk = pbk
            if sid:
                # Truncate garbage from sid
                pre = re.match(r"^[0-9a-fA-F]{2,16}", sid)
                sid_t = pre.group(0) if pre else ""
                if len(sid_t) % 2 == 0 and sid_t:
                    n.sid = sid_t.lower()
            # Strip spx (spiderX) for cleaner dedup
            n.spx = ""

    if net == "ws":
        n.path = fix_wslike_path(_q(q, "path", "p", default="/") or "/", n)
        ed = _q(q, "ed", "max-early-data", "maxearlydata")
        if ed.isdigit():
            n.ed = int(ed)
        n.eh = _q(q, "eh", "earlydataheadername", "early-data-header-name").strip()
    elif net in ("httpupgrade", "xhttp"):
        n.path = fix_wslike_path(_q(q, "path", default="/") or "/", n)
        n.authority = _q(q, "authority").strip() or n.hhost
        if net == "xhttp":
            m_ = trim_enum(_q(q, "mode").strip().lower()) or "auto"
            if m_ not in ("auto", "packet-up", "stream-up", "stream-one"):
                m_ = "auto"
            n.mode = m_
            ex = _q(q, "extra").strip()
            if ex:
                try:
                    json.loads(ex)
                    n.extra = ex
                except Exception:
                    pass
    elif net == "grpc":
        n.service = _q(q, "servicename", "service", "grpc-service-name", "path").strip()
        m_ = trim_enum(_q(q, "mode").strip().lower())
        if m_ in ("gun", "multi"):
            n.mode = m_
    elif net == "tcp":
        ht = _q(q, "headertype", "header", "obfs").strip().lower() or "none"
        ht = trim_enum(ht) or "none"
        if ht not in ("none", "http"):
            ht = "none"
        n.htype = ht
        if ht == "http":
            n.path = fix_wslike_path(_q(q, "path", default="/") or "/", n)


# --- PROTOCOL PARSERS ---

def parse_vless(s: str) -> Node:
    n = Node("vless")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    if "@" not in body:
        raise RejectConfig("No '@' in vless link")
    userinfo, _, hostport = body.rpartition("@")
    cred = unquote(userinfo).strip()
    try:
        n.uuid = str(uuidlib.UUID(cred))
    except Exception:
        raise RejectConfig(f"VLESS ID is not UUID: {cred}")
    n.host, n.port = parse_hostport(hostport)
    enc_raw = _q(q, "encryption").strip()
    if enc_raw and enc_raw.lower() != "none":
        if enc_raw.startswith("mlkem768x25519plus."):
            n.venc = enc_raw
        else:
            n.venc = "none"
    fl = trim_enum(_q(q, "flow").strip().lower())
    if fl in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        n.flow = fl
    fill_transport(n, q, "none")
    if n.flow and (n.net != "tcp" or n.sec not in ("tls", "reality")):
        n.flow = ""
    return n


def parse_trojan(s: str) -> Node:
    n = Node("trojan")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    if "@" not in body:
        raise RejectConfig("No '@' in trojan link")
    userinfo, _, hostport = body.rpartition("@")
    n.password = unquote(userinfo).strip()
    if not n.password:
        raise RejectConfig("Empty trojan password")
    n.host, n.port = parse_hostport(hostport)
    fill_transport(n, q, "tls")
    return n


def parse_ss(s: str) -> Node:
    n = Node("ss")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    n.plugin = _q(q, "plugin").strip()
    if n.plugin:
        raise RejectConfig("SIP003 plugin not supported in Xray 26")
    
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        m = re.match(r"^([^/?]+)(?:/.*)?$", hostport)
        if not m:
            raise RejectConfig(f"Malformed hostport in ss: {hostport}")
        n.host, n.port = parse_hostport(m.group(1))
        ui = unquote(userinfo).strip()
        dec = b64d(ui)
        if dec is not None:
            try:
                t = dec.decode("utf-8").strip()
                if ":" in t:
                    ui = t
            except Exception:
                pass
        if ":" not in ui:
            raise RejectConfig("SS userinfo does not contain method:password")
        n.method, _, n.password = ui.partition(":")
    else:
        dec = b64d(body)
        if dec is None:
            raise RejectConfig("Legacy SS body is not base64")
        try:
            t = dec.decode("utf-8")
            m = re.match(r"^([^:@]*):(.*)@(.+)$", t, re.S)
            if not m:
                raise RejectConfig("Legacy SS is not method:password@host:port")
            n.method, n.password = m.group(1), m.group(2)
            hp = m.group(3).split("?", 1)[0].split("/", 1)[0]
            n.host, n.port = parse_hostport(hp)
        except Exception:
            raise RejectConfig("Failed to parse legacy SS")

    n.method = n.method.strip().lower()
    n.password = n.password.strip()
    if n.method in SS_AEAD_ALIAS:
        n.method = SS_AEAD_ALIAS[n.method]
    if n.method not in SS_METHODS:
        raise RejectConfig(f"SS method '{n.method}' not supported by Xray 26")
    if not n.password or n.password.lower() in JUNK_PASSWORDS:
        raise RejectConfig("Empty or junk SS password")
    if re.search(r"https?://|t\.me", n.password, re.I):
        raise RejectConfig("SS password is ad link")
    return n


def parse_hy2(s: str) -> Node:
    n = Node("hysteria2")
    n.sec = "tls"
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    body = body.strip().strip("/")
    if "@" not in body:
        raise RejectConfig("No auth@host in hysteria2")
    userinfo, _, hostport = body.rpartition("@")
    n.password = unquote(userinfo).strip()
    if not n.password:
        raise RejectConfig("Empty auth in hysteria2")
    
    if hostport.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(.*)$", hostport)
        if not m:
            raise RejectConfig(f"Malformed IPv6 in hy2: {hostport}")
        host, pr = m.group(1), m.group(2)
    else:
        host, sep, pr = hostport.rpartition(":")
        if not sep or not pr:
            raise RejectConfig("No port in hy2")
    
    if pr.isdigit():
        p = int(pr)
        if not (MIN_PORT <= p <= MAX_PORT):
            raise RejectConfig(f"Port outside range: {p}")
        n.port = p
    elif RANGE_RE.match(pr):
        n.port = int(re.match(r"\d{1,5}", pr).group(0))
        n.mport = pr
    else:
        raise RejectConfig(f"Invalid hy2 port: {pr}")
    
    n.host = check_host(host)
    sni = _q(q, "sni", "peer").strip()
    if sni and valid_sni(sni):
        n.sni = sni
    
    ob = trim_enum(_q(q, "obfs").strip().lower())
    obp = _q(q, "obfs-password", "obfspassword", "obfs-param", "obfsparam").strip()
    if ob in ("salamander", "gecko") and obp:
        n.obfs, n.obfsp = ob, obp
    
    mp_ = _q(q, "mport", "ports").strip()
    if mp_ and RANGE_RE.match(mp_):
        n.mport = n.mport or mp_
    
    return n


def parse_vmess(s: str) -> Node:
    n = Node("vmess")
    data = strip_fragment(preprocess(s))[s.index("://") + 3:]
    data = data.split("?", 1)[0].strip().strip("/")
    if data.lstrip().startswith("{"):
        return _vmess_json(n, data.lstrip())
    
    dec = b64d(data)
    if dec is None:
        raise RejectConfig("VMess is not valid base64")
    try:
        text = dec.decode("utf-8").strip()
    except Exception:
        raise RejectConfig("VMess base64 is not UTF-8")
    
    if text.startswith("{"):
        return _vmess_json(n, text)
    raise RejectConfig("VMess is not standard JSON format")


def _vmess_json(n: Node, text: str) -> Node:
    try:
        j = json.loads(text)
    except Exception as e:
        raise RejectConfig(f"VMess JSON decode error: {e}")
    if not isinstance(j, dict):
        raise RejectConfig("VMess JSON is not an object")
    
    low = {str(k).lower(): v for k, v in j.items()}
    def g(*keys, d=""):
        for k in keys:
            v = low.get(k.lower())
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return d

    n.host = check_host(g("add", "address", "server"))
    port_str = g("port", "p")
    if not port_str.isdigit():
        raise RejectConfig(f"Invalid VMess port: {port_str}")
    n.port = int(port_str)
    if not (MIN_PORT <= n.port <= MAX_PORT):
        raise RejectConfig(f"VMess port outside range: {n.port}")
    
    idv = g("id", "uuid", "user")
    try:
        n.uuid = str(uuidlib.UUID(idv))
    except Exception:
        raise RejectConfig(f"VMess ID is not UUID: {idv}")
    
    aid = g("aid", "alterid", "alter_id") or "0"
    n.aid = int(aid) if aid.isdigit() else 0
    
    scy = g("scy", "security", "cipher").lower() or "auto"
    if scy == "zero":
        scy = "none"
    elif scy not in VMESS_SCY:
        scy = "auto"
    n.scy = scy

    tlsraw = g("tls").lower()
    if tlsraw in ("tls", "1", "true"):
        sec = "tls"
    elif tlsraw == "reality":
        sec = "reality"
    else:
        sec = "none"

    q = {
        "type": g("net", "network") or "tcp",
        "security": sec,
        "host": g("host"),
        "path": g("path"),
        "sni": g("sni", "sn", "servername"),
        "alpn": g("alpn"),
        "fp": g("fp", "fingerprint"),
        "pbk": g("pbk", "publickey"),
        "sid": g("sid", "shortid"),
        "servicename": g("servicename", "service"),
        "mode": g("mode"),
        "seed": g("seed"),
        "headertype": g("type") or "none",
        "authority": g("authority"),
        "extra": g("extra"),
    }
    fill_transport(n, q, "none")
    return n


PARSERS = {
    "vless": parse_vless,
    "trojan": parse_trojan,
    "vmess": parse_vmess,
    "ss": parse_ss,
    "hysteria2": parse_hy2
}


# --- CANONICAL URI BUILDER ---

def _canon_qs(prm: list[tuple[str, str]], order: tuple) -> list[tuple[str, str]]:
    idx = {k: i for i, k in enumerate(order)}
    return sorted(prm, key=lambda kv: (idx.get(kv[0], len(idx)), kv[0]))


def build_canonical_uri(n: Node, remark: str = "") -> str:
    """Builds a deterministic, sorted, canonical URI byte-for-byte identical across duplicates."""
    rem_tag = f"#{quote(remark)}" if remark else "#"

    if n.proto == "vmess":
        path = n.path or "/" if n.net in ("ws", "httpupgrade", "xhttp") else (n.service or "")
        host = n.hhost if n.net in ("ws", "httpupgrade", "xhttp") else (n.service or "")
        j = {
            "v": "2",
            "ps": remark,
            "add": n.host,
            "port": str(n.port),
            "id": n.uuid,
            "aid": str(n.aid),
            "scy": n.scy,
            "net": n.net,
            "type": n.htype or "none",
            "host": host,
            "path": path,
            "tls": "tls" if n.sec == "tls" else "reality" if n.sec == "reality" else ""
        }
        if n.sni:
            j["sni"] = n.sni
        if n.alpn:
            j["alpn"] = ",".join(sorted(n.alpn))
        if n.fp:
            j["fp"] = n.fp
        if n.sec == "reality":
            j["pbk"] = n.pbk
            if n.sid:
                j["sid"] = n.sid
        if n.net == "xhttp" and n.mode:
            j["mode"] = n.mode
        
        ordered = {k: j[k] for k in VMESS_JSON_ORDER if k in j}
        blob = base64.b64encode(json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return f"vmess://{blob}"

    if n.proto == "ss":
        ui = base64.urlsafe_b64encode(f"{n.method}:{n.password}".encode()).decode().rstrip("=")
        return f"ss://{ui}@{fh(n.host)}:{n.port}{rem_tag}"

    if n.proto == "hysteria2":
        prm = []
        if n.sni:
            prm.append(("sni", n.sni))
        if n.fp:
            prm.append(("fp", n.fp))
        if n.alpn:
            prm.append(("alpn", ",".join(sorted(n.alpn))))
        if n.obfs:
            prm += [("obfs", n.obfs), ("obfs-password", n.obfsp)]
        if n.mport:
            prm.append(("mport", n.mport))
        prm = _canon_qs(prm, PARAM_ORDER["hysteria2"])
        qs = "&".join(f"{k}={_enc(v)}" for k, v in prm)
        return f"hysteria2://{_enc(n.password)}@{fh(n.host)}:{n.port}" + (f"?{qs}" if qs else "") + rem_tag

    # VLESS & Trojan
    creds = n.uuid if n.proto == "vless" else _enc(n.password)
    prm = []
    if n.proto == "vless" and n.venc and n.venc != "none":
        prm.append(("encryption", n.venc))
    if n.flow:
        prm.append(("flow", n.flow))
    prm.append(("security", n.sec))
    if n.sni:
        prm.append(("sni", n.sni))
    if n.alpn:
        prm.append(("alpn", ",".join(sorted(n.alpn))))
    if n.fp:
        prm.append(("fp", n.fp))
    if n.sec == "reality":
        prm.append(("pbk", n.pbk))
        if n.sid:
            prm.append(("sid", n.sid))
    if n.net != "tcp":
        prm.append(("type", n.net))
    if n.net == "ws":
        prm.append(("path", n.path or "/"))
        if n.hhost:
            prm.append(("host", n.hhost))
        if n.ed is not None:
            prm.append(("ed", str(n.ed)))
        if n.eh:
            prm.append(("eh", n.eh))
    elif n.net in ("httpupgrade", "xhttp"):
        prm.append(("path", n.path or "/"))
        hh = n.authority or n.hhost
        if hh:
            prm.append(("host", hh))
        if n.net == "xhttp" and n.mode:
            prm.append(("mode", n.mode))
    elif n.net == "grpc":
        prm.append(("serviceName", n.service or ""))
        if n.proto == "trojan":
            prm.append(("grpc-service-name", n.service or ""))
        if n.mode:
            prm.append(("mode", n.mode))
    
    prm = _canon_qs(prm, PARAM_ORDER[n.proto])
    qs = "&".join(f"{k}={_enc(v)}" for k, v in prm)
    return f"{n.proto}://{creds}@{fh(n.host)}:{n.port}?{qs}{rem_tag}"


# --- NODE FINGERPRINT FOR DEDUPLICATION ---

def node_fingerprint(n: Node, scope: str = "nekobox") -> str:
    """Computes a 16-byte hex Blake2b fingerprint for deduplication."""
    if scope == "exclave":
        core = (n.proto, n.host, n.port)
    elif scope == "nekobox":
        core = (n.proto, n.host, n.port, n.uuid or n.password, n.net, n.sec, n.mode)
    elif scope == "incy":
        core = (n.proto, n.host, n.port, n.uuid or n.password, n.net, n.sec, n.sni, n.sid)
    else:  # full
        core = (
            n.proto, n.host, n.port, n.uuid, n.password, n.method, n.scy,
            n.net, n.sec, n.flow, n.sni, n.path, n.service, n.pbk, n.sid
        )
    return hashlib.blake2b(repr(core).encode("utf-8", "replace"), digest_size=16).hexdigest()


# --- PUBLIC API ---

def clean_and_parse_uri(uri: str) -> dict | None:
    """High-level clean, repair, and parse of any proxy URI.
    Returns standard config dictionary with canonical raw URI or None if invalid.
    """
    s = uri.strip()
    if not s or "00000000-0000" in s:
        return None
    
    # Extract remark if present
    remark = ""
    i = s.find("#")
    if i >= 0:
        remark = unquote(s[i + 1:]).strip()

    # Match scheme
    m = SCHEME_RE.match(s)
    if not m:
        return None
    raw_proto = m.group(1).lower()
    proto = SCHEME_ALIAS.get(raw_proto, raw_proto)

    if proto not in ACCEPTED:
        return None

    try:
        node = PARSERS[proto](s)
        canon_uri = build_canonical_uri(node, remark)
        fp = node_fingerprint(node, "nekobox")
        return {
            "proto": proto,
            "host": node.host,
            "port": node.port,
            "raw": canon_uri,
            "remark": remark,
            "fingerprint": fp,
            "is_reality": node.sec == "reality",
            "sni": node.sni,
            "net": node.net,
            "sec": node.sec,
            "node": node
        }
    except RejectConfig:
        return None
    except Exception:
        return None
