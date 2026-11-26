# -*- coding: utf-8 -*-
"""Bunker Multi-Source Scraper.
Aggregates VPN configurations across 40+ trusted sources and Telegram feeds.
Features dual-pass Happ device spoofing, Clash YAML ingestion, and GitHub raw auto-fixer.

Credits & Acknowledgments:
Special thanks to Nikita (https://t.me/urlsources / RKPchannel) for Happ device spoofing
architecture, commit-hash auto-fixer logic, and curated Russian hosting lists.
"""

import urllib.request
import urllib.parse
import json
import base64
import logging
import concurrent.futures
import re
import random
import yaml
import html
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
    # 9. OceaniaVPN / StekloVPN Auto-Updated Reality Matrix
    "https://raw.githubusercontent.com/OceaniaVPN/StekloVPN/refs/heads/main/configs/okeania_auto.txt",
    # 10. VlessForU Daily Working Anti-Censorship Configurations
    "https://sub.vlessfo.ru/vlessforu/working_configs.txt",
    # 11. Telegram Alt VPN Obxod (White & Black Lists)
    "https://codeberg.org/telegram-alt_vpn_obxod/obxod_white-black_list/raw/branch/main/subs.txt",
    # 12. OceaniaVPN / StekloVPN User Pool
    "https://raw.githubusercontent.com/OceaniaVPN/StekloVPN/refs/heads/main/configs/user_5512307834_eab99a6c-a05b-48ee-b7a7-729b760e.txt",
    # 13. FreeUlitka MoonPaw Private Reality Relay
    "https://p.kfwl.lol/ua=happ/h=FreeUlitka/https://sub.moonpaw.space/api/sub/eTsCzVjgZAmbnj71",
    # 14. GooseTeam FreeVPN Cracks Community Matrix
    "https://raw.githubusercontent.com/gooseteam-hackers/freevpn-cracks/refs/heads/main/subscription_default.txt",
    # 15. VPN Trade Dedicated Russian Bypass
    "https://v-p-n.trade/sub/for-russia",
    # 16. Mehdirzfx Global Sub Aggregator & Checker (1125+ Verified Feeds)
    "https://mehdirzfx.github.io/v2ray-sub/sub-checker/index.html",
    # 17. ByeWhiteLists Matrix - Russian Anti-DPI & White Lists
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    # 18. Kort0881 RU Best Verified Backend Pool
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part3.txt",
    # 19. F0rc3Run Best Results High-Speed Proxies
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    # 20. NiREvil Reality & VLESS Matrix
    "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/sub/SSTime",
    # 22. AeryxVPN Pozor Bond Direct Feed
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
    # 41. Whoahaow Bypass All Matrix
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    # 42. KFWL / Clippyx Private Matrix (60 nodes)
    "https://sub.clippyx.net:8443/s/NzAyNjc3MDg5OTo0OjNlMjVmZGM5ZmY2MDA3Njg",
    # 43. KFWL / Lunavex Private Sub (305 nodes)
    "https://p.kfwl.lol/https://lunavex.net/sub/Owo3mNLH0sxT3bJm",
    # 44. KFWL / StrelaVPN Dedicated RU Feed (34 nodes)
    "https://sub.strelavpn.ru/QN4FMVLyxdKtTVTJ",
    # 45. KFWL / ROG-SUB UK High Speed Relay (2 nodes)
    "https://rog-sub.co.uk/khQmbBC8kM8TTn_S",
    # 46. KFWL / AleqseiVPN Dedicated Feed (18 nodes)
    "https://www.aleqseivpn.site/sub/mLzmgeLbBCYlI0jfh0HgWA",
    # 47. KFWL / BlackVPN Torrent & Fast Relay (70 nodes)
    "https://p.kfwl.lol/no/https://sub.blackvpn.io/8Z502NguYbbkhxoL",
    # 48. Doroguuuuu XHTTP European Auto-Select Matrix (170 nodes)
    "https://doroguuuuu.ru/exec?url=http%3A%2F%2F144.31.5.17%3A5051%2Fecnnqn%2Fsub%2Fb2JzaGksMTc5NTIzMTUyMAto0DeXMNnf/auto",
    # 49. Doroguuuuu / Happ Decrypted TM Auto Matrix (138 nodes)
    "https://doroguuuuu.ru/exec?url=http%3A%2F%2F144.31.5.17%3A5051%2Fecnnqn%2Fsub%2FdG1tLDE3OTUyMzE3MTkfpFzdQ7T0u/auto",
    # 50. TowshanVpn Richman Google Drive Relay
    "https://www.googleapis.com/drive/v3/files/1wzOHyEeyXAuyf62xCzcfpwOuAUAees2e?alt=media&key=AIzaSyABWhGqO0OH1RvKe-wzyZE1fNvT1kOreGA",
    # 51. TowshanVpn Infinite Google Drive Relay
    "https://www.googleapis.com/drive/v3/files/1JyH-hwc-ZT6t4DOMMvwv2Gr5IpuRDl4K?alt=media&key=AIzaSyCGymbPGMVcK_byQOhvOjAE4Dsk9nb54_E",
    # 52. Diman331 Gist VLESS Reality & XHTTP Matrix (96 nodes)
    "https://gist.githubusercontent.com/Diman331/8c868070c0b5a5ec0c7d94507717b67b/raw/subscription.txt",
    # 53. FLAT447 V2Ray Russian Whitelist Full (100 nodes)
    "https://raw.githubusercontent.com/FLAT447/v2ray-lists/main/WHITE_FULL.txt",
    # 54. VPNKeys Incy Dedicated Russian Whitelist (14 nodes)
    "https://vpnkeys.me/sub/incy/for-russia",
    # 55. V2Hub High-Speed Direct Sub (5 nodes)
    "https://v2hub.link/sub/YGW0Q5b_LdpiR-Qg4lN6yEeL3mPGqVAmgXzv0B6u8Bg",
    # 56. Pozor Bond Unlisted Free Bypass Pool (382 nodes)
    "https://clck.ly/3WnEfT",
    # 57. WSProxy Dedicated Anti-Censorship Relay (10 nodes)
    "https://wsproxy.sub.sos.al/g6ewb39xg3bd8db2hs8",
    # 58. Cepreu54 VLESS Clean RU Matrix (70 nodes)
    "https://raw.githubusercontent.com/Cepreu54/vless-clean/refs/heads/main/clean.txt",
    # 59. YandexDNS Service Bypass Relay (2 nodes)
    "https://dds.yandexdns-api-service.help/sub/97ISLYSEBA/",
    # 60. FreeCFGHub / Ilyacom4ik 2026 Free V2Ray (130 nodes)
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/FreeCFGHub1.txt",
    # 61. Diversan313 Apex Parser Alive Exotic (54 nodes)
    "https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/other/exotic/alive_plain_exotic.txt",
    # 62. HiddifyCode HWID Bypass Matrix (10 nodes)
    "https://is.wepogp.gay/bypass-hwid-lock-3z5O6BFAaJQzGlamvtSo?payload=wiq6mxJkeDA4iTsNc46%2B%2Bmxno5%2B1VG6m5LeYlbNA1kLt5J2vVoj/a6fEi53OHDxSpyGPSCIdbCqC15dCfIQsqgB4wZ0k2tr1AXjNbF9I735NA7YqAzR7xww5XAJz63dh",
    # 63. PiroShokVPN Resub Cloudflare Matrix (56 nodes)
    "https://resub.pirzok6.workers.dev/98165ed40f5fd1c0520402391450d52a",
    # 64. TowshanVpn Decrypted Happ Crypt5 Drive Matrix #1 (107 nodes)
    "https://www.googleapis.com/drive/v3/files/1TYZIGG90fSR9nMKdX8Z0izYZXLMJzGhL?alt=media&key=AIzaSyABWhGqO0OH1RvKe-wzyZE1fNvT1kOreGA",
    # 65. TowshanVpn Decrypted Happ Crypt5 Drive Matrix #2 (64 nodes)
    "https://www.googleapis.com/drive/v3/files/1OeynnrSC3qu1D55QTCMQtkrHSTAy0mHY?alt=media&key=AIzaSyABWhGqO0OH1RvKe-wzyZE1fNvT1kOreGA",
    # 64. ToshibuVPN Bot Sub Matrix (10 nodes)
    "https://tshbotpopup.ru/subscriptions/04920673-035c-410d-94e4-5b1469d3fb6f.txt",
    # 65. Buffetbarko Universal Whitelist VPN (155 nodes)
    "https://raw.githubusercontent.com/Buffetbarko/Universal-Proxy-Config-Parser-/main/whitelist_vpn.txt",
    # 66. Tesla Safepass VLESS Subscription (23 nodes)
    "https://tesla.safepass.click/api/subscription/vless/5140e6d3-737c-49ec-8089-a774bc0b962f",
    # 67. Zonex VPNs Google Drive Media API (37 nodes)
    "https://www.googleapis.com/drive/v3/files/11hSkJep7b3NefeGzhGxuX4N-JhUpypw0?alt=media&key=AIzaSyCPzRhkWhsG0cj9B1wz0lOCnAeipNtPDlw",
    # 68. Freeinternet by Mygalaru Premium Reality Matrix (200 nodes)
    "https://raw.githubusercontent.com/btsk161/Freeinternet_byMygalaru.github.io/refs/heads/main/premium.txt",
    # 69. Buffetbarko Universal Blacklist VPN - Wi-Fi bypass (353 nodes)
    "https://raw.githubusercontent.com/Buffetbarko/Universal-Proxy-Config-Parser-/main/blacklist_vpn.txt",
    # 70. cjsjsuz Hourly Auto Matrix (494 nodes)
    "https://raw.githubusercontent.com/cjsjsuz/sub1h/HEAD/out1h/sub.txt",
    # 71. tqsmmm High-Speed V2Ray Sub (17 nodes)
    "https://raw.githubusercontent.com/tqsmmm/v2ray-sub/main/sub.txt",
    # 72. anna1211688 Shadowrocket Auto Relay (14 nodes)
    "https://anna1211688.github.io/shadowrocket-auto/shadowrocket.txt",
    # 73. FreeCFGHub Master Matrix (2993 nodes)
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/FreeCFGHub.txt",
    # 74. FreeCFGHub All Base64 Matrix (1500+ nodes)
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/all_base64.txt",
    # 75. Pozor Bond LexaVercelbot #1 (Hysteria 2 Direct Relay)
    "https://pozor.bond/sub/ry2627uz9cp7",
    # 76. Pozor Bond LexaVercelbot #2 (VLESS Reality & Fallback)
    "https://pozor.bond/sub/h29399r90wnq",
    # 77. Pozor Bond LexaVercelbot #3 (VLESS Anti-TSPU)
    "https://pozor.bond/sub/utcwry9vug6k",
    # 78. Pozor Bond LexaVercelbot #4 (VLESS High-Speed)
    "https://pozor.bond/sub/fdxvhj7zoh",
    # 79. Pozor Bond LexaVercelbot #5 (VLESS Cloud Node)
    "https://pozor.bond/sub/5qsbui9cf4",
    # 80. Pozor Bond LexaVercelbot #6 (VLESS Mega Matrix 580+ nodes)
    "https://pozor.bond/sub/6i9dnv37cudz",
    # 81. Pozor Bond LexaVercelbot #7 (VLESS Standby Relay)
    "https://pozor.bond/sub/vzal49dpeu1f",
    # 82. st0rer Clash Matrix (Hysteria 2 / VLESS)
    "https://gist.github.com/st0rer/52759ee3f68c3d4b2f2d53c307867471/raw/clash.yaml",
    # 83. skysph-dev V2Ray Aggregator (Trojan / VLESS)
    "https://gist.github.com/skysph-dev/5b55986287442543485b30468db3eb65/raw/v2ray.txt",
    # 84. liketolivefree Kobabi All Subs (21k+ configs, 9k+ Reality)
    "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub_all.txt",
    # 85. kort0881 Russian VLESS / Reality Dedicated Pool
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/output/vless.txt",
    # 86. mermeroo Loon All Nodes Matrix
    "https://raw.githubusercontent.com/mermeroo/Loon/refs/heads/main/all.nodes.txt",
    # 87. barry-far V2Ray Mega Aggregator (8.8k configs, 2.9k Reality)
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    # 88. kasesm Free Configs
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_raw.txt",
    # 89. sakha1370 OpenRay VLESS Matrix (4k configs, 2.1k Reality)
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/kind/vless.txt",
    # 90. Surfboardv2ray TGParse VLESS (5.5k configs, 2.9k Reality)
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    # 91. R3ZARAHIMI Telegram V2Ray & Hy2 Weekly Matrix
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/conf-week.txt",
    # 92. noahclanman Free Xray GCP Verified Pool
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/all/configs.txt",
    # 93. cbusifabcap Daily Free Hysteria2 & VLESS
    "https://cdn.jsdelivr.net/gh/cbusifabcap/daily_free_vpn@main/Z.txt",
    # 94. Mr-Meshky Vify VLESS
    "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt",
    # 95. NamazVPN Community Sub
    "https://sub.namazvpn.workers.dev",
    # 96. Irys DPDNS Auto Sub
    "https://sub.irys.dpdns.org/auto"
]

def clean_source_url(url: str) -> str:
    """Strips invisible zero-width unicode characters and spaces."""
    return url.strip().strip(_ZERO_WIDTH).strip()

# Dynamically load verified community sources from community_sources.txt
COMMUNITY_SOURCES_FILE = Path(__file__).resolve().parent / "community_sources.txt"
if COMMUNITY_SOURCES_FILE.exists():
    try:
        with open(COMMUNITY_SOURCES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                c_url = clean_source_url(line)
                if c_url and not c_url.startswith("#") and c_url not in SOURCES:
                    SOURCES.append(c_url)
    except Exception as e:
        pass

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

    # 0. Check if wrapped in HTML pre tag (e.g. Yandex / Google Translate unblocker)
    if "<pre" in content.lower():
        m = re.search(r"<pre[^>]*>(.*?)</pre>", content, re.DOTALL | re.IGNORECASE)
        if m:
            unwrapped = html.unescape(m.group(1)).strip()
            if any(proto in unwrapped for proto in ["://", "npvs1:", "DARKTUNNEL:", "proxies:"]) or len(unwrapped) > 30:
                content = unwrapped

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
                        for item in custom:
                            if item.startswith(("http://", "https://")):
                                try:
                                    sub_confs = fetch_single_source(item)
                                    found.extend(sub_confs)
                                except Exception:
                                    pass
                            else:
                                found.append(item)
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=28) as executor:
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

    # Load user-contributed configs (.npvt, .npvs, etc.)
    user_contrib_path = Path(__file__).resolve().parent / "user_contrib.txt"
    if user_contrib_path.exists():
        try:
            with open(user_contrib_path, "r", encoding="utf-8") as f:
                u_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                all_configs.extend(u_lines)
                logging.info(f"Loaded {len(u_lines)} user-contributed configs from {user_contrib_path.name}")
        except Exception as e:
            logging.warning(f"Failed to read user_contrib.txt: {e}")

    logging.info(f"Scraped total {len(all_configs)} raw configs.")
    return all_configs
