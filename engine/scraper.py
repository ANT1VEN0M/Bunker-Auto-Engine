import urllib.request
import urllib.parse
import json
import base64
import logging
import concurrent.futures
import re
from pathlib import Path
from engine.npv_parser import (
    extract_all_custom_protocols,
    decode_napsternetv,
    decode_darktunnel,
    parse_ovpn
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

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
    "https://pozor.bond/sub/aeryxvpn"
]

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
    
    # Check if raw lines already have protocols
    if any(proto in raw_text for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://", "npv://", "darktunnel://", "DARKTUNNEL:", "ovpn://"]):
        # If it contains protocols directly, it may also have some base64 blocks
        # Return as is for line-by-line parsing
        return raw_text
    
    # Try Base64 decoding
    try:
        pad = len(raw_text) % 4
        padded = raw_text + ("=" * (4 - pad) if pad else "")
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(proto in decoded for proto in ["://", "npvs1:", "DARKTUNNEL:"]):
            return decoded
    except Exception:
        pass
    
    return raw_text

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
                    l = l.strip()
                    if l.startswith("http") and not l.endswith(".yaml") and not l.endswith(".yml"):
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
    if "mehdirzfx" in url:
        return fetch_mehdirzfx_aggregator()

    configs = []
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "v2rayNG/1.8.5 (Linux; Android 14)",
                "Accept": "*/*"
            }
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="ignore").strip()
            
            # 1. Custom container check (NapsternetV, Dark Tunnel, OpenVPN)
            custom_uris = extract_all_custom_protocols(content)
            if custom_uris:
                configs.extend(custom_uris)

            # 2. Check if JSON config array (e.g. StekloVPN / Xray configs)
            if content.startswith("[") or content.startswith("{"):
                json_uris = parse_json_configs(content)
                if json_uris:
                    configs.extend(json_uris)
            
            if not configs:
                decoded = decode_stream(content)
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
        logging.info(f"Fetched {len(configs)} configs from {url[:50]}...")
    except Exception as e:
        logging.warning(f"Failed fetching {url[:50]}: {e}")
    return configs

def scrape_telegram_public_channels() -> list[str]:
    """Scrapes top active Telegram channels via public web view (t.me/s/) without API keys."""
    tg_file = Path(__file__).resolve().parent / "tg.txt"
    if not tg_file.exists():
        return []
    try:
        with open(tg_file, "r", encoding="utf-8") as f:
            channels = [
                line.strip().replace("https://t.me/", "").replace("@", "").strip("/")
                for line in f if line.strip() and not line.startswith("#")
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
