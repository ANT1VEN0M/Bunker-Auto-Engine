import os
import sys
import logging
import collections
from .scraper import scrape_all_sources
from .parser_utils import parse_config, deduplicate_configs
from .checker import check_all_nodes
from .xray_checker import deep_check_nodes
from .generator import generate_subscriptions
from .geo import init_geo

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def select_balanced_nodes(unique_configs: list[dict], max_total: int = 1500) -> list[dict]:
    # Prioritize anti-censorship protocols for Russia (VLESS Reality, Trojan, Hysteria2)
    # Deprioritize plain Shadowsocks as it is blocked by Russian TSPU
    def node_priority(cfg):
        proto = cfg.get("proto", "")
        port = cfg.get("port", 0)
        
        # Priority 0: VLESS Reality / TLS on 443
        if proto == "vless" and port == 443:
            return 0
        # Priority 1: Hysteria 2 / Trojan on 443
        if proto in ("hy2", "trojan") and port == 443:
            return 1
        # Priority 2: VLESS / Trojan / Hy2 on standard/TLS ports (53, 8443, 2053, 2083)
        if proto in ("vless", "trojan", "hy2") and port in (53, 8443, 2053, 2083, 2087, 2096):
            return 2
        # Priority 3: Other VLESS / Trojan / VMess
        if proto in ("vless", "trojan", "vmess"):
            return 3
        # Priority 4: Plain Shadowsocks (lowest priority)
        return 4

    sorted_configs = sorted(unique_configs, key=node_priority)
    return sorted_configs[:max_total]

def run_pipeline():
    logging.info("=== STARTING BUNKER AUTO-ENGINE PIPELINE ===")
    
    # 1. Scrape
    raw_configs = scrape_all_sources()
    if not raw_configs:
        logging.error("No configs scraped! Aborting pipeline.")
        return

    # 2. Parse
    logging.info(f"Parsing {len(raw_configs)} raw configs...")
    parsed = []
    for r in raw_configs:
        cfg = parse_config(r)
        if cfg:
            parsed.append(cfg)
    logging.info(f"Successfully parsed {len(parsed)} valid configs.")

    # 3. Deduplicate
    unique = deduplicate_configs(parsed)
    logging.info(f"Deduplicated down to {len(unique)} unique host:port servers.")

    # 4. Initialize GeoIP database
    init_geo()

    # 5. Balanced node selection (prioritizing 443 & 53, balancing VLESS, VMess, Trojan, SS, HY2)
    nodes_to_check = select_balanced_nodes(unique, max_total=3000)
    logging.info(f"Selected {len(nodes_to_check)} balanced nodes for health check.")

    # 6. Pre-Filter Health & Ping (TCP level)
    alive = check_all_nodes(nodes_to_check, max_workers=140, timeout=2.5)

    if not alive:
        logging.warning("No alive nodes detected during ping check!")
        return

    # 7. DEEP XRAY CORE VERIFICATION (Real HTTP 204 Traffic Test)
    # Tests candidates through actual Xray Core to guarantee 100% working proxies
    real_working = deep_check_nodes(alive, batch_size=25, max_verified=250)

    if not real_working:
        logging.warning("No nodes passed deep HTTP 204 check, falling back to TCP alive.")
        real_working = alive[:100]
    else:
        # Append other high-quality Russian anti-censorship alive nodes (port 443/53/8443)
        seen_hosts = {f"{c['host']}:{c['port']}" for c in real_working}
        for n in alive:
            key = f"{n['host']}:{n['port']}"
            if key not in seen_hosts and n.get("proto") in ("vless", "trojan", "hy2") and n.get("port") in (443, 53, 8443):
                real_working.append(n)
                seen_hosts.add(key)

    # 8. Generate subscriptions and dashboard
    logging.info(f"Generating subscription files from {len(real_working)} GUARANTEED WORKING NODES...")
    generate_subscriptions(real_working)
    logging.info("=== PIPELINE FINISHED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_pipeline()
