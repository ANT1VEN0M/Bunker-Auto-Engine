import socket
import time
import logging
import concurrent.futures
from .geo import resolve_host_to_ip, get_country_code, get_asn_info, is_russian_wl_hosting

def check_single_node(cfg: dict, timeout: float = 2.0) -> dict | None:
    host = cfg.get("host", "")
    port = cfg.get("port", 0)
    
    if not (1 <= port <= 65535):
        return None
    
    ip = resolve_host_to_ip(host)
    if not ip:
        return None
    
    start_t = time.perf_counter()
    proto = cfg.get("proto", "").lower()
    try:
        if proto in ("hy2", "hysteria2", "tuic", "wireguard"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Send lightweight probe packet to test UDP socket reachability
            sock.connect((ip, port))
            sock.send(b"\x00" * 16)
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()
        elapsed = time.perf_counter() - start_t
        ping_ms = max(1, int(elapsed * 1000))
        
        country = get_country_code(ip)
        asn, org = get_asn_info(ip)
        is_wl, wl_name = is_russian_wl_hosting(ip, asn=asn)
        
        result = dict(cfg)
        result["ip"] = ip
        result["ping_ms"] = ping_ms
        result["country"] = country
        result["asn"] = asn
        result["org"] = org
        result["is_wl_hosting"] = is_wl
        result["wl_hosting"] = wl_name
        return result
    except (socket.timeout, socket.error, OSError, OverflowError, ValueError):
        return None

def check_all_nodes(configs: list[dict], max_workers: int = 120, timeout: float = 2.0) -> list[dict]:
    logging.info(f"Starting health & ping check for {len(configs)} nodes (workers={max_workers}, timeout={timeout}s)...")
    alive_nodes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cfg = {executor.submit(check_single_node, cfg, timeout): cfg for cfg in configs}
        for future in concurrent.futures.as_completed(future_to_cfg):
            try:
                res = future.result()
                if res:
                    alive_nodes.append(res)
            except Exception:
                continue
    
    wl_count = sum(1 for n in alive_nodes if n.get("is_wl_hosting"))
    logging.info(f"Health check completed: {len(alive_nodes)} / {len(configs)} nodes alive! (Russian WL Hostings: {wl_count})")
    return alive_nodes
