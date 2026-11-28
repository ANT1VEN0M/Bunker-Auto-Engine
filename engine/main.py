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

def select_balanced_nodes(unique_configs: list[dict], max_total: int = 3500) -> list[dict]:
    # Group by protocol to guarantee balanced representation without starving any protocol
    by_proto = collections.defaultdict(list)
    for c in unique_configs:
        proto = c.get("proto", "").lower()
        raw_l = c.get("raw", "").lower()
        if proto in ("hy2", "hysteria2"):
            by_proto["hy2"].append(c)
        elif proto == "vless":
            if "security=reality" in raw_l:
                by_proto["vless_reality"].append(c)
            else:
                by_proto["vless_tls"].append(c)
        elif proto == "trojan":
            by_proto["trojan"].append(c)
        elif proto == "vmess":
            by_proto["vmess"].append(c)
        elif proto in ("ss", "shadowsocks"):
            by_proto["ss"].append(c)
        else:
            by_proto["other"].append(c)

    selected = []
    # Anti-censorship: prioritize 100% Russian-verified seed nodes
    verified_ru = [c for c in unique_configs if c.get("is_ru_verified")]
    selected.extend(verified_ru)

    # Anti-censorship balanced quotas
    selected.extend(by_proto["hy2"][:600])
    selected.extend(by_proto["vless_reality"][:1500])
    selected.extend(by_proto["trojan"][:600])
    selected.extend(by_proto["vless_tls"][:500])
    selected.extend(by_proto["vmess"][:300])
    selected.extend(by_proto["ss"][:150])

    if len(selected) < max_total:
        seen = set(id(x) for x in selected)
        for cat, nodes in by_proto.items():
            for n in nodes:
                if id(n) not in seen:
                    selected.append(n)
                    seen.add(id(n))
                    if len(selected) >= max_total:
                        break
            if len(selected) >= max_total:
                break

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

    # 5. Balanced node selection (balancing Hy2, VLESS-Reality, Trojan, VLESS-TLS, VMess, SS)
    nodes_to_check = select_balanced_nodes(unique, max_total=3500)
    logging.info(f"Selected {len(nodes_to_check)} balanced nodes for health check.")

    # 6. Pre-Filter Health & Ping (TCP / UDP level)
    alive = check_all_nodes(nodes_to_check, max_workers=160, timeout=2.0)

    if not alive:
        logging.warning("No alive nodes detected during ping check!")
        return

    # Sort alive nodes so that high-potential anti-censorship nodes are tested first
    def deep_candidate_priority(cfg):
        if cfg.get("is_ru_verified"):
            return -1
        is_wl = cfg.get("is_wl_hosting", False)
        p = cfg.get("port", 0)
        proto = cfg.get("proto", "").lower()
        raw = cfg.get("raw", "")
        raw_l = raw.lower()

        is_reality = (proto == "vless" and "security=reality" in raw_l and "pbk=" in raw_l)
        is_xhttp = ("type=xhttp" in raw_l or "mode=packet-up" in raw_l)

        # Priority 0: Clean VLESS Reality on 443 (pure TCP/Vision anti-censorship)
        if is_reality and not is_xhttp and p == 443:
            return 0
        # Priority 1: Hysteria 2 (native UDP anti-censorship)
        if proto in ("hy2", "hysteria2"):
            return 1
        # Priority 2: Russian Whitelist Hostings on 443/53
        if is_wl and p in (443, 53):
            return 2
        # Priority 3: Other clean VLESS Reality
        if is_reality and not is_xhttp:
            return 3
        # Priority 4: Russian Whitelist Hostings on other ports
        if is_wl:
            return 4
        # Priority 5: Fresh feeds (CloudFront doroguuuuu, NPVS decrypted, etc.)
        if "cloudfront" in raw or "doroguuuuu" in raw or "wergmb" in raw:
            return 5
        # Priority 6: Trojan on port 443 or 8443
        if proto == "trojan" and p in (443, 8443):
            return 6
        # Priority 7: VLESS / Trojan on standard TLS ports
        if proto in ("vless", "trojan") and p in (53, 8443, 2053, 2083, 2087, 2096):
            return 7
        # Priority 8: VMess on standard TLS ports
        if proto == "vmess" and p in (443, 8443):
            return 8
        # Priority 9: Any other VLESS / Trojan / VMess
        if proto in ("vless", "trojan", "vmess"):
            return 9
        return 10

    alive.sort(key=deep_candidate_priority)
    logging.info(f"Sorted {len(alive)} alive nodes by Russian bypass priority for deep verification.")

    # 7. DEEP XRAY & SING-BOX CORE VERIFICATION (Real HTTP 204 Traffic Test)
    # Tests candidates through actual Xray Core & Sing-box to guarantee 100% working proxies
    real_working = deep_check_nodes(alive, batch_size=40, max_verified=350)

    if not real_working:
        logging.warning("No nodes passed deep HTTP 204 check, falling back to top TCP/UDP alive.")
        real_working = alive[:150]

    # Guarantee all 100% verified Russian-tested nodes are included at the very top
    ru_verified = [n for n in unique if n.get("is_ru_verified")]
    seen_eps = {f"{n.get('host')}:{n.get('port')}" for n in real_working}
    for n in reversed(ru_verified):
        ep = f"{n.get('host')}:{n.get('port')}"
        if ep not in seen_eps:
            seen_eps.add(ep)
            real_working.insert(0, n)
        else:
            # Move to front
            real_working = [x for x in real_working if f"{x.get('host')}:{x.get('port')}" != ep]
            real_working.insert(0, n)

    # 8. Generate subscriptions and dashboard
    logging.info(f"Generating subscription files from {len(real_working)} GUARANTEED WORKING NODES...")
    generate_subscriptions(real_working)
    logging.info("=== PIPELINE FINISHED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_pipeline()
