"""
npv_parser.py - Universal Multi-Format Protocol Parser for Bunker-Auto-Engine.
Supports:
  1. NapsternetV / NPV Tunnel (.npvt, .npvs, npv://, npvs1: sentinels, Xray JSON outbounds)
  2. Dark Tunnel (.dark, .dt, darktunnel://, DARKTUNNEL: AES-GCM encrypted/unlocked payloads)
  3. OpenVPN (.ovpn, ovpn:// base64 URI)
Converts all extracted configurations into standard proxy URIs (vless://, vmess://, trojan://, ss://, hy2://, ovpn://).
"""

import base64
import json
import logging
import os
import re
import urllib.parse
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

NPV_SENTINEL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"


# ============================================================================
# 1. NAPSTERNETV / NPV TUNNEL PARSER (.npvt, .npvs, npv://, npvs1:)
# ============================================================================

def decode_sentinel_token(tok: str) -> Optional[str]:
    """Decode base64 token used in NapsternetV npvs1: sentinels."""
    for pad in ("", "=", "==", "==="):
        t = tok + pad
        for alt in (None, "-_"):
            try:
                b = base64.b64decode(t, altchars=alt)
                return b.decode("utf-8", errors="replace")
            except Exception:
                pass
    return None


def decode_sentinels(s: str) -> str:
    """Replace npvs1:BASE64 sentinels with decoded strings."""
    if not isinstance(s, str):
        return s
    prefix = "npvs1:"
    out = []
    while prefix in s:
        before, s = s.split(prefix, 1)
        out.append(before)
        j = 0
        while j < len(s) and s[j] in NPV_SENTINEL_ALPHABET:
            j += 1
        tok = s[:j]
        s = s[j:]
        dec = decode_sentinel_token(tok)
        if dec is not None:
            out.append(dec)
        else:
            out.append(prefix + tok)
    out.append(s)
    return "".join(out)


def walk_decode_sentinels(v: Any) -> Any:
    """Recursively decode npvs1: sentinels inside nested dicts/lists."""
    if isinstance(v, str):
        return decode_sentinels(v)
    elif isinstance(v, dict):
        return {k: walk_decode_sentinels(val) for k, val in v.items()}
    elif isinstance(v, list):
        return [walk_decode_sentinels(val) for val in v]
    return v


def parse_v2ray_outbound(outbound: dict, remark: str = "") -> Optional[str]:
    """Convert an Xray/V2ray outbound dictionary into a standard URI."""
    proto = str(outbound.get("protocol", "")).lower()
    settings = outbound.get("settings", {}) or {}
    stream = outbound.get("streamSettings", {}) or {}
    tag = outbound.get("tag", remark) or remark or "Bunker-NPV"
    remark_q = urllib.parse.quote(str(tag))

    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    extra: Dict[str, str] = {"type": network}
    if security and security != "none":
        extra["security"] = security

    # WebSocket
    if network == "ws":
        ws = stream.get("wsSettings", {}) or {}
        if ws.get("path"):
            extra["path"] = ws["path"]
        host = (ws.get("headers", {}) or {}).get("Host")
        if host:
            extra["host"] = host

    # gRPC
    elif network == "grpc":
        grpc = stream.get("grpcSettings", {}) or {}
        if grpc.get("serviceName"):
            extra["serviceName"] = grpc["serviceName"]
        if grpc.get("multiMode"):
            extra["mode"] = "multi"

    # XHTTP / HTTPUpgrade
    elif network in ("xhttp", "httpupgrade"):
        xh = stream.get("xhttpSettings", {}) or stream.get("httpupgradeSettings", {}) or {}
        if xh.get("path"):
            extra["path"] = xh["path"]
        if xh.get("host"):
            extra["host"] = xh["host"]

    # TLS / Reality
    if security == "tls":
        tls = stream.get("tlsSettings", {}) or {}
        if tls.get("serverName"):
            extra["sni"] = tls["serverName"]
        if tls.get("fingerprint"):
            extra["fp"] = tls["fingerprint"]
        if tls.get("alpn"):
            extra["alpn"] = ",".join(tls["alpn"]) if isinstance(tls["alpn"], list) else str(tls["alpn"])
        if tls.get("allowInsecure"):
            extra["allowInsecure"] = "1"
    elif security == "reality":
        real = stream.get("realitySettings", {}) or {}
        if real.get("serverName"):
            extra["sni"] = real["serverName"]
        if real.get("publicKey"):
            extra["pbk"] = real["publicKey"]
        if real.get("shortId"):
            extra["sid"] = real["shortId"]
        if real.get("fingerprint"):
            extra["fp"] = real["fingerprint"]
        if real.get("spiderX"):
            extra["spx"] = urllib.parse.quote(real["spiderX"])

    # VLESS
    if proto == "vless":
        vnext = (settings.get("vnext") or [{}])[0]
        server, port = vnext.get("address"), vnext.get("port")
        if not server or not port:
            return None
        user = (vnext.get("users") or [{}])[0]
        uuid = user.get("id", "")
        if user.get("flow"):
            extra["flow"] = user["flow"]
        qs = urllib.parse.urlencode(extra)
        return f"vless://{uuid}@{server}:{port}?{qs}#{remark_q}"

    # VMess
    elif proto == "vmess":
        vnext = (settings.get("vnext") or [{}])[0]
        server, port = vnext.get("address"), vnext.get("port")
        if not server or not port:
            return None
        user = (vnext.get("users") or [{}])[0]
        vmess_dict = {
            "v": "2",
            "ps": str(tag),
            "add": str(server),
            "port": str(port),
            "id": user.get("id", ""),
            "aid": str(user.get("alterId", 0)),
            "scy": "auto",
            "net": network,
            "type": "none",
            "host": extra.get("host", ""),
            "path": extra.get("path", ""),
            "tls": security if security != "none" else "",
            "sni": extra.get("sni", ""),
        }
        b64_str = base64.b64encode(json.dumps(vmess_dict).encode("utf-8")).decode("utf-8")
        return f"vmess://{b64_str}"

    # Trojan
    elif proto == "trojan":
        srv = (settings.get("servers") or [{}])[0]
        server, port = srv.get("address"), srv.get("port")
        if not server or not port:
            return None
        password = srv.get("password", "")
        qs = urllib.parse.urlencode(extra)
        return f"trojan://{password}@{server}:{port}?{qs}#{remark_q}"

    # Shadowsocks
    elif proto in ("shadowsocks", "ss"):
        srv = (settings.get("servers") or [{}])[0]
        server, port = srv.get("address"), srv.get("port")
        if not server or not port:
            return None
        method = srv.get("method", "aes-256-gcm")
        password = srv.get("password", "")
        auth = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8")
        return f"ss://{auth}@{server}:{port}#{remark_q}"

    # Hysteria 2
    elif proto in ("hysteria", "hysteria2", "hy2"):
        server = settings.get("address")
        port = settings.get("port")
        hy_set = stream.get("hysteriaSettings", {}) or {}
        auth = hy_set.get("auth", "") or settings.get("auth", "")
        if server and port and auth:
            qs = f"?sni={extra['sni']}" if "sni" in extra else ""
            return f"hy2://{auth}@{server}:{port}{qs}#{remark_q}"

    return None


def parse_napsternetv_item(item: dict) -> List[str]:
    """Parse a single item or profile from a NapsternetV container."""
    links = []
    item = walk_decode_sentinels(item)
    profile = item.get("v2rayProfile") if isinstance(item.get("v2rayProfile"), dict) else item
    remark = (
        profile.get("remarks")
        or profile.get("remark")
        or profile.get("ps")
        or item.get("name")
        or "Bunker-NPV"
    )

    # 1. Check embedded v2rayJson
    v2ray_json_str = item.get("v2rayJson") or profile.get("v2rayJson")
    if v2ray_json_str:
        try:
            if isinstance(v2ray_json_str, str):
                vjson = json.loads(v2ray_json_str)
            else:
                vjson = v2ray_json_str
            for ob in vjson.get("outbounds", []):
                link = parse_v2ray_outbound(ob, remark)
                if link:
                    links.append(link)
        except Exception:
            pass

    # 2. Check direct outbounds array
    if not links and "outbounds" in item:
        for ob in item.get("outbounds", []):
            link = parse_v2ray_outbound(ob, remark)
            if link:
                links.append(link)

    # 3. Check legacy flat profile
    if not links:
        server = profile.get("server") or profile.get("address") or profile.get("host") or profile.get("add")
        port = profile.get("serverPort") or profile.get("port")
        if server and port:
            proto = str(profile.get("protocol") or profile.get("type") or item.get("type") or "").lower()
            network = profile.get("network") or profile.get("net") or "tcp"
            path = profile.get("path") or ""
            host = profile.get("host") or ""
            sni = profile.get("sni") or host
            security = profile.get("security") or ("tls" if profile.get("tls") else "none")
            pbk = profile.get("publicKey") or profile.get("pbk")
            sid = profile.get("shortId") or profile.get("sid")
            flow = profile.get("flow")
            uuid = profile.get("uuid") or profile.get("id") or ""
            password = profile.get("password") or ""
            remark_q = urllib.parse.quote(str(remark))

            q_params: Dict[str, str] = {"type": network}
            if security and security != "none":
                q_params["security"] = security
            if sni:
                q_params["sni"] = sni
            if path:
                q_params["path"] = path
            if host:
                q_params["host"] = host
            if pbk:
                q_params["pbk"] = pbk
            if sid:
                q_params["sid"] = sid
            if flow:
                q_params["flow"] = flow
            qs = urllib.parse.urlencode(q_params)

            if "vless" in proto or (uuid and not password and ("reality" in security or flow)):
                links.append(f"vless://{uuid}@{server}:{port}?{qs}#{remark_q}")
            elif "vmess" in proto or ("scy" in profile or profile.get("aid") is not None):
                vmess_dict = {
                    "v": "2",
                    "ps": str(remark),
                    "add": str(server),
                    "port": str(port),
                    "id": str(uuid),
                    "aid": str(profile.get("alterId", 0)),
                    "scy": "auto",
                    "net": str(network),
                    "type": "none",
                    "host": str(host),
                    "path": str(path),
                    "tls": str(security if security != "none" else ""),
                    "sni": str(sni),
                }
                b64_str = base64.b64encode(json.dumps(vmess_dict).encode("utf-8")).decode("utf-8")
                links.append(f"vmess://{b64_str}")
            elif "trojan" in proto or (password and not uuid):
                links.append(f"trojan://{password}@{server}:{port}?{qs}#{remark_q}")
            elif "ss" in proto or "shadowsocks" in proto:
                method = profile.get("method", "aes-256-gcm")
                auth = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8")
                links.append(f"ss://{auth}@{server}:{port}#{remark_q}")

    return links


def decode_napsternetv(content_or_link: str) -> List[str]:
    """
    Main decoder for NapsternetV / NPV Tunnel configurations.
    Accepts:
      - npv://BASE64
      - Raw JSON export (.npvt / .npvs)
      - Strings containing npvs1: sentinels
    """
    content = content_or_link.strip()
    if not content:
        return []

    # If URI starts with npv://
    if content.startswith("npv://"):
        raw_b64 = content[6:].strip()
        pad = len(raw_b64) % 4
        if pad:
            raw_b64 += "=" * (4 - pad)
        try:
            content = base64.b64decode(raw_b64).decode("utf-8", errors="ignore").strip()
        except Exception:
            return []

    # Replace sentinels
    if "npvs1:" in content:
        content = decode_sentinels(content)

    results: List[str] = []

    # Try parsing JSON
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                results.extend(parse_napsternetv_item(item))
    except Exception:
        # Check if lines inside decoded stream are standard URIs
        for line in content.splitlines():
            line = line.strip()
            if any(line.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://", "hy2://")):
                results.append(line)

    return results


# ============================================================================
# 2. DARK TUNNEL PARSER (.dark, .dt, darktunnel://, DARKTUNNEL:)
# ============================================================================

def derive_dark_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation used by Dark Tunnel."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required for AES-GCM decryption")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
    )
    return kdf.derive(password.encode("utf-8"))


def decrypt_darktunnel_payload(encrypted_b64: str, password: str = "") -> Optional[str]:
    """Decrypt DARKTUNNEL: AES-GCM container."""
    if not CRYPTO_AVAILABLE:
        logging.warning("cryptography not available, cannot decrypt AES-GCM payload")
        return None
    try:
        pad = len(encrypted_b64) % 4
        if pad:
            encrypted_b64 += "=" * (4 - pad)
        data = base64.b64decode(encrypted_b64)
        if len(data) < 16 + 12 + 16:
            return None
        salt = data[:16]
        iv = data[16:28]
        ciphertext = data[28:]

        # Try user password, empty password, or common default passwords
        passwords_to_try = [password, "", "darktunnel", "dark", "1234", "admin"]
        for pwd in passwords_to_try:
            try:
                key = derive_dark_key(pwd, salt)
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(iv, ciphertext, None)
                return decrypted.decode("utf-8", errors="ignore")
            except Exception:
                continue
    except Exception as e:
        logging.debug(f"DarkTunnel decrypt failed: {e}")
    return None


def darktunnel_dict_to_uri(cfg: dict) -> Optional[str]:
    """Convert parsed Dark Tunnel configuration dictionary into standard URI."""
    proto_raw = str(cfg.get("protocol", "")).upper()
    server = cfg.get("serverHost") or cfg.get("host") or cfg.get("server") or ""
    port = cfg.get("serverPort") or cfg.get("port")
    name = cfg.get("name") or cfg.get("remarks") or "Bunker-DarkTunnel"
    name_q = urllib.parse.quote(str(name))

    if not server or not port:
        return None

    sni = cfg.get("sniHost") or cfg.get("sni") or ""
    path = cfg.get("path") or "/"
    uuid = cfg.get("uuid") or cfg.get("id") or ""
    password = cfg.get("password") or ""
    inject = str(cfg.get("injectionMode", "")).upper()
    is_tls = "SNI" in inject or "SSL" in proto_raw or bool(sni)

    # VLESS
    if "VLESS" in proto_raw or (uuid and "VLESS" in str(cfg)):
        extra = {"type": "tcp"}
        if is_tls:
            extra["security"] = "tls"
            if sni:
                extra["sni"] = sni
        if path and path != "/":
            extra["type"] = "ws"
            extra["path"] = path
        qs = urllib.parse.urlencode(extra)
        return f"vless://{uuid}@{server}:{port}?{qs}#{name_q}"

    # VMess
    elif "VMESS" in proto_raw:
        vmess_dict = {
            "v": "2",
            "ps": name,
            "add": server,
            "port": str(port),
            "id": uuid,
            "aid": str(cfg.get("alterId", 0)),
            "scy": cfg.get("security", "auto"),
            "net": "ws" if path and path != "/" else "tcp",
            "type": "none",
            "host": sni,
            "path": path,
            "tls": "tls" if is_tls else "",
            "sni": sni,
        }
        b64_str = base64.b64encode(json.dumps(vmess_dict).encode("utf-8")).decode("utf-8")
        return f"vmess://{b64_str}"

    # Trojan
    elif "TROJAN" in proto_raw:
        extra = {"security": "tls"}
        if sni:
            extra["sni"] = sni
        qs = urllib.parse.urlencode(extra)
        return f"trojan://{password}@{server}:{port}?{qs}#{name_q}"

    # Shadowsocks
    elif "SHADOWSOCKS" in proto_raw or "SS" in proto_raw:
        method = cfg.get("security") or "aes-256-gcm"
        auth = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8")
        return f"ss://{auth}@{server}:{port}#{name_q}"

    # Hysteria UDP
    elif "HYSTERIA" in proto_raw:
        qs = f"?sni={sni}" if sni else ""
        return f"hy2://{password}@{server}:{port}{qs}#{name_q}"

    return None


def decode_darktunnel(content_or_link: str, password: str = "") -> List[str]:
    """
    Main decoder for Dark Tunnel (.dark, .dt, darktunnel://, DARKTUNNEL:).
    Converts to standard proxy links.
    """
    content = content_or_link.strip()
    if not content:
        return []

    # Strip URI scheme
    if content.startswith("darktunnel://"):
        content = content[13:].strip()

    # If DARKTUNNEL: AES-GCM encrypted package
    if content.startswith("DARKTUNNEL:"):
        enc_payload = content[11:].strip()
        decrypted = decrypt_darktunnel_payload(enc_payload, password)
        if decrypted:
            content = decrypted
        else:
            return []

    # If base64-encoded JSON or URL
    if not content.startswith("{") and not content.startswith("["):
        try:
            pad = len(content) % 4
            if pad:
                content += "=" * (4 - pad)
            dec_bytes = base64.b64decode(content)
            content = dec_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

    # Check for direct standard URIs inside
    uris = []
    if any(p in content for p in ("vless://", "vmess://", "trojan://", "ss://", "hy2://")):
        for line in content.splitlines():
            line = line.strip()
            if any(line.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://", "hy2://")):
                uris.append(line)
        if uris:
            return uris

    # Try parsing JSON
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else [data]
        for it in items:
            if isinstance(it, dict):
                u = darktunnel_dict_to_uri(it)
                if u:
                    uris.append(u)
    except Exception:
        pass

    return uris


# ============================================================================
# 3. OPENVPN PARSER (.ovpn, ovpn://)
# ============================================================================

def parse_ovpn(content_or_link: str, default_name: str = "Bunker-OpenVPN") -> Optional[Dict[str, Any]]:
    """
    Parse an OpenVPN (.ovpn) configuration file or ovpn:// URI.
    Extracts server, port, protocol, ciphers, and bundles a shareable ovpn:// URI.
    """
    content = content_or_link.strip()
    if not content:
        return None

    # Handle ovpn://base64#remark
    remark = default_name
    if content.startswith("ovpn://"):
        main = content[7:]
        if "#" in main:
            main, remark = main.split("#", 1)
            remark = urllib.parse.unquote(remark)
        pad = len(main) % 4
        if pad:
            main += "=" * (4 - pad)
        try:
            content = base64.b64decode(main).decode("utf-8", errors="ignore")
        except Exception:
            return None

    # Extract directives
    remote_match = re.search(r"^\s*remote\s+([^\s]+)(?:\s+(\d+))?(?:\s+(udp|tcp))?", content, re.MULTILINE | re.IGNORECASE)
    if not remote_match:
        return None

    host = remote_match.group(1).strip()
    port = int(remote_match.group(2) or 1194)
    proto_from_remote = remote_match.group(3)

    proto_match = re.search(r"^\s*proto\s+(udp|tcp)", content, re.MULTILINE | re.IGNORECASE)
    proto = (proto_from_remote or (proto_match.group(1) if proto_match else "udp")).lower()

    cipher_match = re.search(r"^\s*cipher\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
    cipher = cipher_match.group(1).strip() if cipher_match else "AES-256-GCM"

    dev_match = re.search(r"^\s*dev\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
    dev = dev_match.group(1).strip() if dev_match else "tun"

    # Build standard ovpn:// base64 URI
    enc = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    ovpn_uri = f"ovpn://{enc}#{urllib.parse.quote(remark)}"

    return {
        "proto": "ovpn",
        "host": host,
        "port": port,
        "transport": proto,
        "cipher": cipher,
        "dev": dev,
        "remark": remark,
        "raw_ovpn": content,
        "uri": ovpn_uri
    }


# ============================================================================
# 4. UNIVERSAL DETECTOR & EXTRACTOR
# ============================================================================

def extract_all_custom_protocols(text_or_url: str) -> List[str]:
    """
    Scans any input string or downloaded payload for NapsternetV (.npvt, npv://),
    Dark Tunnel (.dark, .dt, darktunnel://), or OpenVPN (.ovpn, ovpn://)
    and returns a normalized list of standard proxy URIs.
    """
    text = text_or_url.strip()
    if not text:
        return []

    collected: List[str] = []

    # 1. Dark Tunnel check
    if "darktunnel://" in text or "DARKTUNNEL:" in text or '"serverHost"' in text:
        dt_links = decode_darktunnel(text)
        if dt_links:
            collected.extend(dt_links)

    # 2. NapsternetV check
    if "npv://" in text or "npvs1:" in text or "v2rayProfile" in text or "v2rayJson" in text:
        npv_links = decode_napsternetv(text)
        if npv_links:
            collected.extend(npv_links)

    # 3. OpenVPN check
    if "ovpn://" in text or ("client" in text and "remote " in text and "dev " in text):
        parsed_ovpn = parse_ovpn(text)
        if parsed_ovpn and parsed_ovpn.get("uri"):
            collected.append(parsed_ovpn["uri"])

    return collected
