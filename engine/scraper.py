import urllib.request
import base64
import logging
import concurrent.futures

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
    "https://random.solovyov-jenya2004.workers.dev/"
]

def decode_stream(raw_text: str) -> str:
    raw_text = raw_text.strip()
    if not raw_text:
        return ""
    
    # Check if raw lines already have protocols
    if any(proto in raw_text for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://"]):
        # If it contains protocols directly, it may also have some base64 blocks
        # Return as is for line-by-line parsing
        return raw_text
    
    # Try Base64 decoding
    try:
        pad = len(raw_text) % 4
        padded = raw_text + ("=" * (4 - pad) if pad else "")
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(proto in decoded for proto in ["://"]):
            return decoded
    except Exception:
        pass
    
    return raw_text

def fetch_single_source(url: str) -> list[str]:
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
            content = resp.read().decode("utf-8", errors="ignore")
            decoded = decode_stream(content)
            for line in decoded.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # If a line itself is base64
                if not "://" in line and len(line) > 30:
                    try:
                        p = len(line) % 4
                        sub_dec = base64.b64decode(line + ("=" * (4 - p) if p else "")).decode("utf-8", errors="ignore")
                        for sub_l in sub_dec.splitlines():
                            sub_l = sub_l.strip()
                            if any(sub_l.startswith(proto) for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://"]):
                                configs.append(sub_l)
                    except Exception:
                        pass
                elif any(line.startswith(proto) for proto in ["vless://", "vmess://", "trojan://", "ss://", "hy2://", "tuic://"]):
                    configs.append(line)
        logging.info(f"Fetched {len(configs)} configs from {url[:50]}...")
    except Exception as e:
        logging.warning(f"Failed fetching {url[:50]}: {e}")
    return configs

def scrape_all_sources() -> list[str]:
    all_configs = []
    logging.info(f"Starting scraping from {len(SOURCES)} sources in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(fetch_single_source, url): url for url in SOURCES}
        for future in concurrent.futures.as_completed(future_to_url):
            configs = future.result()
            all_configs.extend(configs)
    
    logging.info(f"Scraped total {len(all_configs)} raw configs.")
    return all_configs
