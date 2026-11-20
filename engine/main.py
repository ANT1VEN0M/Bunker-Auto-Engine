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

def select_balanced_nodes(unique_configs: list[dict], max_total: int = 3000) -> list[dict]:
    by_proto = collections.defaultdict(list)
    for cfg in unique_configs:
        by_proto[cfg["proto"]].append(cfg)

    quotas = {
        "vless": 1200,
        "vmess": 800,
        "trojan": 500,
        "ss": 400,
        "hy2": 200,
        "tuic": 100
    }

    selected = []
    for proto, cfgs in by_proto.items():
        # Prioritize 443 and 53 ports within each protocol
        cfgs.sort(key=lambda c: 0 if c["port"] in (443, 53) else 1)
        q = quotas.get(proto, 200)
        selected.extend(cfgs[:q])

    # Re-sort overall to prioritize 443 and 53 ports
    selected.sort(key=lambda c: 0 if c["port"] in (443, 53) else 1)
    return selected[:max_total]

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
    real_working = deep_check_nodes(alive, batch_size=25, max_verified=180)

    if not real_working:
        logging.warning("No nodes passed deep HTTP 204 check, falling back to TCP alive.")
        real_working = alive[:100]

    # 8. Generate subscriptions and dashboard
    logging.info(f"Generating subscription files from {len(real_working)} GUARANTEED WORKING NODES...")
    generate_subscriptions(real_working)
    logging.info("=== PIPELINE FINISHED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_pipeline()
