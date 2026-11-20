import urllib.request
import base64
import logging
import concurrent.futures

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SOURCES = [
    # Top Russian Anti-Censorship Sources (didloaa / Roskompozor / Solovyov / Igareck)
    "https://random.solovyov-jenya2004.workers.dev/",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl",
    "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/bl",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    # Barry-Far (updated every 15 min)
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    # 4Diana
    "https://raw.githubusercontent.com/EEvanescence/4Diana/main/AllConfigsSub.txt",
    # Au1rxx (tested active)
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    # MahdiBland aggregator
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    # Freefq
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    # Pawdroid
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    # Telegram collector mirrors
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all"
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
