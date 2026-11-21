import urllib.request
import urllib.parse
import json
import base64
import logging
import concurrent.futures
import re
import random
import yaml
from pathlib import Path
from engine.npv_parser import (
    extract_all_custom_protocols,
    decode_napsternetv,
    decode_darktunnel,
    parse_ovpn
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

_ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff"

_GH_HASH_RE = re.compile(
    r"^(?P<prefix>https://raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/"
    r"|https://github\.com/[^/\s]+/[^/\s]+/raw/)"
    r"(?P<sha>[0-9a-fA-F]{7,64})"
    r"(?P<rest>/\S*)$"
)

HAPP_APP_VERSIONS = (
    "4.8.0", "4.7.9", "4.7.8", "4.7.7", "4.7.5", "4.7.4", "4.7.3", "4.7.2",
    "4.7.1", "4.7.0", "4.6.9", "4.6.8", "4.6.7", "4.6.6", "4.6.5", "4.6.4",
)
ANDROID_OS_VERSIONS = ("13", "14", "15", "16")
ANDROID_MODELS = (
    "SM-S938B", "SM-S928B", "SM-S918B", "SM-A556B", "SM-A546B",
    "Pixel 9 Pro XL", "Pixel 9 Pro", "Pixel 9", "Pixel 8 Pro", "Pixel 8",
    "2407FRK8EC", "23127PN0CG", "23116PN5BC",
    "CPH2609", "CPH2581", "NE2213",
)

SOURCES = [
    # 1. Igareck Russian Anti-Censorship (White Lists for Mobile & Restrictive Firewalls)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # 2. Igareck Russian Anti-Censorship (Black Lists for Wireline ISPs: Rostelecom, etc.)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    # 3. Igareck Russian Anti-Censorship (Black Lists for Mobile ISPs: MTS, MegaFon, Beeline, Tele2)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    # 4. Kizyak VPN 4.0 - Moscow-tested Anti-TSPU Reality Nodes (Hourly updated)
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/main/kizyakbeta8.txt",
    # 5. Kizyak VPN 4.0 - Black List bypass nodes
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/main/kizyakbeta6BL.txt",
    # 6. Kizyak VPN 4.0 - Test RU verified nodes
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/main/kizyaktestru.txt",
    # 7. Aviamasters Free Russia - Verified VLESS/Reality configs
    "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt",
    # 8. Aviamasters Free Russia - RU CIDR whitelist configs
    "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/ru_configs.txt",
    # 9. Solovyov Community Workers Anti-Censorship Aggregator
    "https://random.solovyov-jenya2004.workers.dev/",
    # 10. H1Clayd Dedicated Private Anti-Censorship Feed
    "https://s-25562.nl2.h1clayd.click/sub/d92038b6-b470-4267-9c69-2c649bf3f4a4",
    # 11. OceaniaVPN / StekloVPN Auto-Updated Reality Matrix
    "https://raw.githubusercontent.com/OceaniaVPN/StekloVPN/refs/heads/main/configs/okeania_auto.txt",
    # 12. HappCluchi Community Workers Free VPN
    "https://freevpn.happcluchi.workers.dev/",
    # 13. VlessForU Daily Working Anti-Censorship Configurations
    "https://sub.vlessfo.ru/vlessforu/working_configs.txt",
    # 14. Telegram Alt VPN Obxod (White & Black Lists)
    "https://codeberg.org/telegram-alt_vpn_obxod/obxod_white-black_list/raw/branch/main/subs.txt",
    # 15. OceaniaVPN / StekloVPN User Pool
    "https://raw.githubusercontent.com/OceaniaVPN/StekloVPN/refs/heads/main/configs/user_5512307834_eab99a6c-a05b-48ee-b7a7-729b760e.txt",
    # 16. Wepogp HWID Bypass Feed (Auto location reality)
    "https://is.wepogp.gay/bypass-hwid-lock-3z5O6BFAaJQzGlamvtSo?payload=nB6WFdc033pP4/nQclqdVvlQzxtVyf3foOMtnfl/MMPP4UJtJ1LdUha8hHnFXIOVXTkBVQ2ju2FDRejIa%2BWvNPTjB1V0Ic52FHGcG0HfF%2Bn/27HIfPKA95ILu11jRpSBr9FiHdHNs9ragsAo6/d5qQ%3D%3D",
    # 17. FreeUlitka MoonPaw Private Reality Relay
    "https://p.kfwl.lol/ua=happ/h=FreeUlitka/https://sub.moonpaw.space/api/sub/eTsCzVjgZAmbnj71",
    # 18. Gidroksi Anti-Blacklist Reality Pool
    "https://gidroksi.fun/black-list",
    # 19. GooseTeam FreeVPN Cracks Community Matrix
    "https://raw.githubusercontent.com/gooseteam-hackers/freevpn-cracks/refs/heads/main/subscription_default.txt",
    # 20. VPN Trade Dedicated Russian Bypass
    "https://v-p-n.trade/sub/for-russia",
    # 21. Mehdirzfx Global Sub Aggregator & Checker (1125+ Verified Feeds)
    "https://mehdirzfx.github.io/v2ray-sub/sub-checker/index.html",
    # 22. ByeWhiteLists Matrix - Russian Anti-DPI & White Lists
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    # 23. Kort0881 RU Best Verified Backend Pool
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part3.txt",
    # 24. F0rc3Run Best Results High-Speed Proxies
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    # 25. NiREvil Reality & VLESS Matrix
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime",
    # 26. AeryxVPN Official Workers Cloudflare Relay (VLESS & Hysteria2)
    "https://aeryxvpn-sub.aeryxvpn.workers.dev",
    # 27. AeryxVPN Mos.ru Unblockable Russian GitLab Mirror
    "https://hub.mos.ru/cheesyx/aeryx-mirror/raw/main/mirror.json",
    # 28. AeryxVPN Pozor Bond Direct Feed
    "https://pozor.bond/sub/aeryxvpn",
    # 29. Kort0881 Verified Private Poster - Russia Nodes
    "https://raw.githubusercontent.com/kort0881/vpn-private-poster/main/checked/Russia_part1_sub.txt",
    # 30. Kort0881 Verified Private Poster - Europe Nodes
    "https://raw.githubusercontent.com/kort0881/vpn-private-poster/main/checked/Europe_part1_sub.txt",
    # 31. Kort0881 Verified Private Poster - Asia Nodes
    "https://raw.githubusercontent.com/kort0881/vpn-private-poster/main/checked/Asia_part1_sub.txt",
    # 32. Kort0881 Verified Private Poster - Unknown Nodes
    "https://raw.githubusercontent.com/kort0881/vpn-private-poster/main/checked/Unknown_part1_sub.txt",
    # 33. Kort0881 Verified Private Poster - Other Nodes
    "https://raw.githubusercontent.com/kort0881/vpn-private-poster/main/checked/Other_part1_sub.txt",
    # 34. FastNodes Japan Dedicated Verified Feed
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/JP.txt",
    # 35. LimeHi Russian Whitelist
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/whitelist.txt",
    # 36. LimeHi Russian Blacklist
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/blacklist.txt",
    # 37. Theakres VPN All In One
    "https://github.com/theakres/VPN/raw/main/all",
    # 38. Zieng2 VLESS Universal Whitelist
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    # 39. Roskompozor Gitlab Mirror Whitelist
    "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl",
    # 40. Roskompozor Gitlab Mirror Blacklist
    "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/bl",
    # 41. Whoahaow Bypass All Matrix
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"
]

def clean_source_url(url: str) -> str:
    """Strips invisible zero-width unicode characters and spaces."""
    return url.strip().strip(_ZERO_WIDTH).strip()

def fix_github_raw_url(url: str) -> str:
    """Auto-fixes GitHub raw URLs with commit hashes, replacing sha with main."""
    m = _GH_HASH_RE.match(url)
    if not m:
        return url
    prefix = m.group("prefix")
    rest = m.group("rest")
    return f"{prefix}main{rest}"

def generate_happ_device_headers() -> tuple[dict[str, str], str]:
    """Generates authentic Android device emulation headers for Happ / gated panels."""
    app = random.choice(HAPP_APP_VERSIONS)
    model = random.choice(ANDROID_MODELS)
    os_ver = random.choice(ANDROID_OS_VERSIONS)
    hwid = f"{random.getrandbits(63) | (1 << 63):016x}"
    ua_num = str(random.getrandbits(63) | (1 << 63))
    ua = f"Happ/{app}/Android/{ua_num}"
    headers = {
        "User-Agent": ua,
        "X-HWID": hwid,
        "X-Device-OS": "Android",
        "X-Ver-OS": os_ver,
        "X-Device-Model": model,
        "X-App-Version": app,
        "Accept": "*/*"
    }
    return headers, hwid

def parse_clash_yaml(content: str) -> list[str]:
    """Extracts VLESS, VMess, Trojan, Shadowsocks, Hysteria2 from Clash YAML subscriptions."""
    uris = []
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return []
        proxies = data.get("proxies")
        if not isinstance(proxies, list):
            return []
        
        for p in proxies:
            if not isinstance(p, dict):
                continue
            ptype = str(p.get("type", "")).lower()
            name = str(p.get("name", ""))
            server = p.get("server")
            port = p.get("port")
            if not server or not port:
                continue
            tag = f"#{urllib.parse.quote(name)}" if name else ""

            if ptype == "vless":
                uuid = p.get("uuid")
                if not uuid:
                    continue
                q = {}
                q["encryption"] = str(p.get("encryption", "none"))
                if p.get("flow"):
                    q["flow"] = str(p["flow"])
                
                # TLS / Reality
                tls = p.get("tls")
                reality_opts = p.get("reality-opts") or {}
                if reality_opts:
                    q["security"] = "reality"
                    sni = p.get("servername") or p.get("sni")
                    if sni: q["sni"] = str(sni)
                    fp = p.get("client-fingerprint") or "chrome"
                    if fp: q["fp"] = str(fp)
                    pbk = reality_opts.get("public-key") or reality_opts.get("public_key")
                    if pbk: q["pbk"] = str(pbk)
                    sid = reality_opts.get("short-id") or reality_opts.get("short_id")
                    if sid: q["sid"] = str(sid)
                elif tls:
                    q["security"] = "tls"
                    sni = p.get("servername") or p.get("sni")
                    if sni: q["sni"] = str(sni)
                    fp = p.get("client-fingerprint")
                    if fp: q["fp"] = str(fp)
                    if p.get("skip-cert-verify"): q["allowInsecure"] = "1"
                
                # Network / transport
                net = str(p.get("network", "tcp")).lower()
                if net not in ("", "tcp"):
                    q["type"] = net
                    if net in ("ws", "httpupgrade"):
                        ws_opts = p.get("ws-opts") or {}
                        path = ws_opts.get("path")
                        if path: q["path"] = str(path)
                        headers = ws_opts.get("headers") or {}
                        h = headers.get("Host") or headers.get("host")
                        if h: q["host"] = str(h)
                    elif net == "grpc":
                        g_opts = p.get("grpc-opts") or {}
                        svc = g_opts.get("grpc-service-name")
                        if svc: q["serviceName"] = str(svc)
                    elif net == "xhttp":
                        xh = p.get("xhttp-opts") or {}
                        if xh.get("path"): q["path"] = str(xh["path"])
                        if xh.get("host"): q["host"] = str(xh["host"])
                
                query_str = urllib.parse.urlencode(sorted(q.items()))
                uris.append(f"vless://{uuid}@{server}:{port}?{query_str}{tag}")

            elif ptype == "trojan":
                password = p.get("password")
                if not password:
                    continue
                q = {}
                sni = p.get("sni") or p.get("servername")
                if sni: q["sni"] = str(sni)
                alpn = p.get("alpn")
                if isinstance(alpn, list) and alpn: q["alpn"] = ",".join(str(x) for x in alpn)
                if p.get("skip-cert-verify"): q["allowInsecure"] = "1"
                net = str(p.get("network", "tcp")).lower()
                if net not in ("", "tcp"):
                    q["type"] = net
                    if net == "ws":
                        ws_opts = p.get("ws-opts") or {}
                        if ws_opts.get("path"): q["path"] = str(ws_opts["path"])
                        headers = ws_opts.get("headers") or {}
                        if headers.get("Host"): q["host"] = str(headers["Host"])
                    elif net == "grpc":
                        g_opts = p.get("grpc-opts") or {}
                        if g_opts.get("grpc-service-name"): q["serviceName"] = str(g_opts["grpc-service-name"])
                query_str = ("?" + urllib.parse.urlencode(sorted(q.items()))) if q else ""
                uris.append(f"trojan://{password}@{server}:{port}{query_str}{tag}")

            elif ptype in ("hysteria2", "hy2"):
                password = p.get("password") or p.get("auth") or ""
                q = {}
                sni = p.get("sni") or p.get("servername")
                if sni: q["sni"] = str(sni)
                if p.get("skip-cert-verify"): q["insecure"] = "1"
                obfs = p.get("obfs")
                if obfs:
                    q["obfs"] = str(obfs)
                    obfs_pass = p.get("obfs-password")
                    if obfs_pass: q["obfs-password"] = str(obfs_pass)
                query_str = ("?" + urllib.parse.urlencode(sorted(q.items()))) if q else ""
                auth_str = f"{password}@" if password else ""
                uris.append(f"hy2://{auth_str}{server}:{port}{query_str}{tag}")

            elif ptype in ("ss", "shadowsocks"):
                cipher = p.get("cipher")
                password = p.get("password")
                if cipher and password:
                    raw_userinfo = f"{cipher}:{password}".encode("utf-8")
                    userinfo = base64.urlsafe_b64encode(raw_userinfo).decode("ascii").rstrip("=")
                    uris.append(f"ss://{userinfo}@{server}:{port}{tag}")

            elif ptype == "vmess":
                uuid = p.get("uuid")
                if not uuid:
                    continue
                net = str(p.get("network", "tcp")).lower()
                ws_opts = p.get("ws-opts") or {}
                headers = ws_opts.get("headers") or {}
                tls = p.get("tls")
                vobj = {
                    "v": "2",
                    "ps": name,
                    "add": str(server),
                    "port": str(port),
                    "id": str(uuid),
                    "aid": str(p.get("alterId", 0)),
                    "scy": str(p.get("cipher", "auto")),
                    "net": net,
                    "type": "none",
                    "host": str(headers.get("Host", "")),
                    "path": str(ws_opts.get("path", "")),
                    "tls": "tls" if tls else "",
                    "sni": str(p.get("servername", "")),
                }
                b64_v = base64.b64encode(json.dumps(vobj).encode("utf-8")).decode("ascii")
                uris.append(f"vmess://{b64_v}")
    except Exception:
        pass
    return uris

def parse_json_configs(content: str) -> list[str]:
    uris = []
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else [data]
        for item in items:
            remarks = item.get("remarks", "")
            for o in item.get("outbounds", []):
                proto = o.get("protocol")
                settings = o.get("settings", {})
                stream = o.get("streamSettings", {})
                tag = o.get("tag", remarks)

                if proto == "vless":
                    vnext = settings.get("vnext", [{}])[0]
                    addr = vnext.get("address")
                    port = vnext.get("port")
                    user = vnext.get("users", [{}])[0]
                    uuid = user.get("id")
                    flow = user.get("flow", "")
                    if not addr or not port or not uuid:
                        continue
                    network = stream.get("network", "tcp")
                    security = stream.get("security", "none")
                    params = [f"type={network}"]
                    if security: params.append(f"security={security}")
                    if flow: params.append(f"flow={flow}")
                    if security == "reality":
                        real = stream.get("realitySettings", {})
                        if real.get("serverName"): params.append(f"sni={real['serverName']}")
                        if real.get("publicKey"): params.append(f"pbk={real['publicKey']}")
                        if real.get("shortId"): params.append(f"sid={real['shortId']}")
                        if real.get("fingerprint"): params.append(f"fp={real['fingerprint']}")
                    elif security == "tls":
                        tls = stream.get("tlsSettings", {})
                        if tls.get("serverName"): params.append(f"sni={tls['serverName']}")
                        if tls.get("fingerprint"): params.append(f"fp={tls['fingerprint']}")
                    if network == "xhttp":
                        xh = stream.get("xhttpSettings", {})
                        if xh.get("path"): params.append(f"path={urllib.parse.quote(xh['path'])}")
                        if xh.get("host"): params.append(f"host={xh['host']}")
                        if xh.get("mode"): params.append(f"mode={xh['mode']}")
                    elif network == "ws":
                        ws = stream.get("wsSettings", {})
                        if ws.get("path"): params.append(f"path={urllib.parse.quote(ws['path'])}")
                        if ws.get("headers", {}).get("Host"): params.append(f"host={ws['headers']['Host']}")
                    query = "&".join(params)
                    t = f"#{urllib.parse.quote(tag)}" if tag else ""
                    uris.append(f"vless://{uuid}@{addr}:{port}?{query}{t}")

                elif proto in ("hysteria", "hysteria2", "hy2"):
                    addr = settings.get("address")
                    port = settings.get("port")
                    hy_set = stream.get("hysteriaSettings", {})
                    auth = hy_set.get("auth", "") or settings.get("auth", "")
                    tls = stream.get("tlsSettings", {})
                    sni = tls.get("serverName", "")
                    if addr and port and auth:
                        params = []
                        if sni: params.append(f"sni={sni}")
                        q = ("?" + "&".join(params)) if params else ""
                        t = f"#{urllib.parse.quote(tag)}" if tag else ""
                        uris.append(f"hy2://{auth}@{addr}:{port}{q}{t}")

                elif proto == "trojan":
                    servers = settings.get("servers", [{}])[0]
                    addr = servers.get("address")
                    port = servers.get("port")
                    password = servers.get("password")
                    if addr and port and password:
                        tls = stream.get("tlsSettings", {})
                        sni = tls.get("serverName", "")
                        params = []
                        if sni: params.append(f"sni={sni}")
                        q = ("?" + "&".join(params)) if params else ""
                        t = f"#{urllib.parse.quote(tag)}" if tag else ""
                        uris.append(f"trojan://{password}@{addr}:{port}{q}{t}")
    except Exception:
        pass
    return uris

def decode_stream(raw_text: str) -> str:
    raw_text = raw_text.strip()
    if not raw_text:
        return ""
    
    # Check if raw lines already have protocols or yaml
    if any(proto in raw_text for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://", "npv://", "darktunnel://", "DARKTUNNEL:", "ovpn://", "proxies:"]):
        return raw_text
    
    # Try Base64 decoding
    try:
        pad = len(raw_text) % 4
        padded = raw_text + ("=" * (4 - pad) if pad else "")
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(proto in decoded for proto in ["://", "npvs1:", "DARKTUNNEL:", "proxies:"]):
            return decoded
    except Exception:
        pass
    
    return raw_text

def extract_configs_from_content(content: str) -> list[str]:
    configs = []
    if not content:
        return configs

    # 1. Custom container check (NapsternetV, Dark Tunnel, OpenVPN)
    custom_uris = extract_all_custom_protocols(content)
    if custom_uris:
        configs.extend(custom_uris)

    # 2. Check if JSON config array (e.g. StekloVPN / Xray configs)
    if content.startswith("[") or content.startswith("{"):
        json_uris = parse_json_configs(content)
        if json_uris:
            configs.extend(json_uris)

    # 3. Check Clash YAML
    if ("proxies:" in content or "proxies :" in content) and ("type:" in content or "type :" in content):
        yaml_uris = parse_clash_yaml(content)
        if yaml_uris:
            configs.extend(yaml_uris)

    # 4. Stream and Base64 line parsing
    if not configs:
        decoded = decode_stream(content)
        # Check if decoded payload was Clash YAML
        if ("proxies:" in decoded or "proxies :" in decoded) and ("type:" in decoded or "type :" in decoded):
            yaml_uris = parse_clash_yaml(decoded)
            if yaml_uris:
                configs.extend(yaml_uris)

        if not configs:
            for line in decoded.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Direct check for custom schemes
                if line.startswith("darktunnel://") or line.startswith("DARKTUNNEL:"):
                    dt_parsed = decode_darktunnel(line)
                    if dt_parsed:
                        configs.extend(dt_parsed)
                elif line.startswith("npv://") or "npvs1:" in line:
                    npv_parsed = decode_napsternetv(line)
                    if npv_parsed:
                        configs.extend(npv_parsed)
                elif line.startswith("ovpn://"):
                    configs.append(line)
                # If a line itself is base64
                elif not "://" in line and len(line) > 30:
                    try:
                        p = len(line) % 4
                        sub_dec = base64.b64decode(line + ("=" * (4 - p) if p else "")).decode("utf-8", errors="ignore")
                        for sub_l in sub_dec.splitlines():
                            sub_l = sub_l.strip()
                            if any(sub_l.startswith(proto) for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://", "ovpn://"]):
                                configs.append(sub_l)
                    except Exception:
                        pass
                elif any(line.startswith(proto) for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://", "ovpn://"]):
                    configs.append(line)
    return configs

def fetch_url_content(url: str, headers: dict[str, str], timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore").strip()

def fetch_mehdirzfx_aggregator() -> list[str]:
    configs = []
    try:
        readme_url = "https://raw.githubusercontent.com/mehdirzfx/v2ray-sub/main/README.md"
        req = urllib.request.Request(readme_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            md = resp.read().decode("utf-8", errors="ignore")
            blocks = re.findall(r"```[^\n]*\n(.*?)```", md, re.DOTALL)
            links = []
            for b in blocks:
                for l in b.splitlines():
                    l = clean_source_url(l)
                    if l.startswith("http"):
                        links.append(l)

            # Prioritize Russian bypass, VLESS, Reality, and high-yield subscriptions
            ru_and_vless = [l for l in links if any(k in l.lower() for k in ["ru", "russia", "white", "black", "vless", "hysteria"])]
            other_good = [l for l in links if l not in ru_and_vless]
            selected = (ru_and_vless[:15] + other_good[:5])

            logging.info(f"mehdirzfx: Aggregating {len(selected)} sub feeds from 1100+ repository index...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                future_to_sub = {ex.submit(fetch_single_source, sub_url): sub_url for sub_url in selected}
                for f in concurrent.futures.as_completed(future_to_sub):
                    try:
                        res = f.result()
                        if res:
                            configs.extend(res)
                    except Exception:
                        pass
        logging.info(f"mehdirzfx aggregator returned {len(configs)} total configs.")
    except Exception as e:
        logging.warning(f"Failed aggregating mehdirzfx: {e}")
    return configs

def fetch_single_source(url: str) -> list[str]:
    url = clean_source_url(url)
    url = fix_github_raw_url(url)

    if "mehdirzfx" in url:
        return fetch_mehdirzfx_aggregator()

    # Pass 1: Happ client device emulation (X-HWID, X-Device-Model, X-Ver-OS, UA Happ, ?hwid=...)
    # This unlocks private panels and Happ subscriptions that reject generic crawlers.
    happ_headers, hwid = generate_happ_device_headers()
    happ_url = url
    if "hwid=" not in url:
        sep = "&" if "?" in url else "?"
        happ_url = f"{url}{sep}hwid={hwid}"

    try:
        content = fetch_url_content(happ_url, headers=happ_headers, timeout=10)
        configs = extract_configs_from_content(content)
        if configs:
            logging.info(f"[Happ-Pass] Fetched {len(configs)} configs from {url[:50]}...")
            return configs
    except Exception:
        pass

    # Pass 2: Fallback to standard v2rayNG client
    standard_headers = {
        "User-Agent": "v2rayNG/1.8.5 (Linux; Android 14)",
        "Accept": "*/*"
    }
    try:
        content = fetch_url_content(url, headers=standard_headers, timeout=10)
        configs = extract_configs_from_content(content)
        if configs:
            logging.info(f"[Standard-Pass] Fetched {len(configs)} configs from {url[:50]}...")
            return configs
    except Exception as e:
        logging.warning(f"Failed fetching {url[:50]}: {e}")

    return []

def scrape_telegram_public_channels() -> list[str]:
    """Scrapes top active Telegram channels via public web view (t.me/s/) without API keys."""
    tg_file = Path(__file__).resolve().parent / "tg.txt"
    if not tg_file.exists():
        return []
    try:
        with open(tg_file, "r", encoding="utf-8") as f:
            channels = [
                clean_source_url(line).replace("https://t.me/", "").replace("@", "").strip("/")
                for line in f if clean_source_url(line) and not clean_source_url(line).startswith("#")
            ]
    except Exception:
        return []

    selected = channels[:45]
    logging.info(f"Telegram Public Scraper: Scraping {len(selected)} channels in parallel...")
    collected = []

    def fetch_channel(ch: str) -> list[str]:
        found = []
        url = f"https://t.me/s/{ch}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                uris = re.findall(r'(vless://[^\s\"<>]+|trojan://[^\s\"<>]+|ss://[^\s\"<>]+|hy2://[^\s\"<>]+|hysteria2://[^\s\"<>]+|happ://[^\s\"<>]+|v2raytun://[^\s\"<>]+|incy://[^\s\"<>]+)', html)
                for u in uris:
                    custom = extract_all_custom_protocols(u)
                    if custom:
                        found.extend(custom)
                    else:
                        found.append(u)
        except Exception:
            pass
        return found

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for res in ex.map(fetch_channel, selected):
            if res:
                collected.extend(res)

    logging.info(f"Telegram Public Scraper yielded {len(collected)} configs from channels.")
    return collected

def scrape_all_sources() -> list[str]:
    all_configs = []
    logging.info(f"Starting scraping from {len(SOURCES)} sources in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(fetch_single_source, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            configs = future.result()
            all_configs.extend(configs)
    
    # Also scrape curated Telegram channels
    try:
        tg_configs = scrape_telegram_public_channels()
        if tg_configs:
            all_configs.extend(tg_configs)
    except Exception as e:
        logging.warning(f"Telegram channel scraper warning: {e}")

    logging.info(f"Scraped total {len(all_configs)} raw configs.")
    return all_configs
