import socket
import time
import logging
import concurrent.futures
from .geo import resolve_host_to_ip, get_country_code

def check_single_node(cfg: dict, timeout: float = 2.0) -> dict | None:
    host = cfg["host"]
    port = cfg["port"]
    
    ip = resolve_host_to_ip(host)
    if not ip:
        return None
    
    start_t = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        elapsed = time.perf_counter() - start_t
        ping_ms = max(1, int(elapsed * 1000))
        
        country = get_country_code(ip)
        
        result = dict(cfg)
        result["ip"] = ip
        result["ping_ms"] = ping_ms
        result["country"] = country
        return result
    except (socket.timeout, socket.error, OSError):
        return None

def check_all_nodes(configs: list[dict], max_workers: int = 120, timeout: float = 2.0) -> list[dict]:
    logging.info(f"Starting health & ping check for {len(configs)} nodes (workers={max_workers}, timeout={timeout}s)...")
    alive_nodes = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cfg = {executor.submit(check_single_node, cfg, timeout): cfg for cfg in configs}
        for future in concurrent.futures.as_completed(future_to_cfg):
            res = future.result()
            if res:
                alive_nodes.append(res)
    
    logging.info(f"Health check completed: {len(alive_nodes)} / {len(configs)} nodes are alive!")
    return alive_nodes
