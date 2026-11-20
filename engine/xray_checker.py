import os
import sys
import json
import base64
import re
import time
import shutil
import logging
import urllib.request
import subprocess
import concurrent.futures
from urllib.parse import parse_qs, unquote
from .geo import get_country_code

XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v24.11.5/Xray-linux-64.zip"
XRAY_BIN = "/tmp/xray"

def ensure_xray():
    if os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return True
    logging.info("Downloading official Xray-core for Linux deep testing...")
    zip_path = "/tmp/xray.zip"
    try:
        urllib.request.urlretrieve(XRAY_URL, zip_path)
        subprocess.run(["unzip", "-q", "-o", zip_path, "xray", "-d", "/tmp"], check=True)
        os.chmod(XRAY_BIN, 0o755)
        logging.info("Xray-core ready.")
        return True
    except Exception as e:
        logging.error(f"Failed to prepare Xray binary: {e}")
        return False

def uri_to_outbound(uri: str, tag: str) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vless://"):
            match = re.match(r"^vless://([^@]+)@([^:/?#]+):(\d+)(.*)$", uri)
            if not match:
                return None
            uuid, host, port_str, rest = match.groups()
            port = int(port_str)
            if not (1 <= port <= 65535):
                return None

            query_str = rest.split("#", 1)[0]
            if query_str.startswith("?"):
                query_str = query_str[1:]
            q = parse_qs(query_str)

            flow = q.get("flow", [""])[0]
            sec = q.get("security", ["none"])[0]
            net = q.get("type", ["tcp"])[0]
            sni = q.get("sni", [""])[0]
            fp = q.get("fp", ["chrome"])[0]
            pbk = q.get("pbk", [""])[0]
            sid = q.get("sid", [""])[0]
            path = q.get("path", ["/"])[0]
            host_header = q.get("host", [""])[0]
            service_name = q.get("serviceName", [""])[0]

            if sec == "reality":
                # Xray REALITY only supports tcp/raw, h2, grpc, xhttp
                if net not in ["tcp", "raw", "grpc", "h2", "xhttp"]:
                    return None
                if not pbk:
                    return None

            if flow == "xtls-rprx-vision" and net not in ["tcp", "raw"]:
                flow = ""

            stream = {"network": net, "security": sec}
            if sec == "reality":
                stream["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": fp,
                    "show": False,
                    "publicKey": pbk,
                    "shortId": sid,
                    "spiderX": ""
                }
                if net == "grpc":
                    stream["grpcSettings"] = {
                        "serviceName": service_name,
                        "multiMode": False
                    }
            elif sec == "tls":
                stream["tlsSettings"] = {
                    "serverName": sni or host,
                    "allowInsecure": True
                }
                if net == "grpc":
                    stream["grpcSettings"] = {
                        "serviceName": service_name,
                        "multiMode": False
                    }

            if net == "ws":
                stream["wsSettings"] = {
                    "path": path,
                    "headers": {"Host": host_header or sni or host}
                }

            return {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": "none",
                            "flow": flow
                        }]
                    }]
                },
                "streamSettings": stream
            }

        elif uri.startswith("vmess://"):
            b64_part = uri[8:]
            pad = len(b64_part) % 4
            if pad:
                b64_part += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            net = data.get("net", "tcp")
            sec = data.get("tls", "none")
            port = int(data.get("port", 0))
            if not (1 <= port <= 65535):
                return None

            stream = {"network": net, "security": "tls" if sec == "tls" else "none"}
            if sec == "tls":
                stream["tlsSettings"] = {
                    "serverName": data.get("sni") or data.get("host") or data.get("add"),
                    "allowInsecure": True
                }
            if net == "ws":
                stream["wsSettings"] = {
                    "path": data.get("path", "/"),
                    "headers": {"Host": data.get("host", "")}
                }

            return {
                "tag": tag,
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": data.get("add"),
                        "port": port,
                        "users": [{
                            "id": data.get("id"),
                            "alterId": int(data.get("aid", 0)),
                            "security": "auto"
                        }]
                    }]
                },
                "streamSettings": stream
            }

        elif uri.startswith("trojan://"):
            match = re.match(r"^trojan://([^@]+)@([^:/?#]+):(\d+)(.*)$", uri)
            if not match:
                return None
            password, host, port_str, rest = match.groups()
            port = int(port_str)
            if not (1 <= port <= 65535):
                return None

            query_str = rest.split("#", 1)[0]
            if query_str.startswith("?"):
                query_str = query_str[1:]
            q = parse_qs(query_str)
            sni = q.get("sni", [""])[0]

            return {
                "tag": tag,
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni or host,
                        "allowInsecure": True
                    }
                }
            }

        elif uri.startswith("ss://"):
            main = uri[5:].split("#")[0]
            if "@" in main:
                auth, hostport = main.split("@", 1)
                pad = len(auth) % 4
                if pad:
                    auth += "=" * (4 - pad)
                method, password = base64.b64decode(auth).decode("utf-8", errors="ignore").split(":", 1)
            else:
                pad = len(main) % 4
                if pad:
                    main += "=" * (4 - pad)
                dec = base64.b64decode(main).decode("utf-8", errors="ignore")
                auth, hostport = dec.split("@", 1)
                method, password = auth.split(":", 1)
            parts = hostport.split(":")
            host = parts[0].strip("[]")
            port = int(parts[1])
            if not (1 <= port <= 65535):
                return None

            return {
                "tag": tag,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "method": method,
                        "password": password
                    }]
                }
            }
    except Exception:
        pass
    return None

def test_xray_batch(batch: list[dict], base_port: int = 11000) -> list[dict]:
    inbounds = []
    outbounds = []
    rules = []
    valid_items = []

    for i, cfg in enumerate(batch):
        tag = f"out_{i}"
        in_tag = f"in_{i}"
        port = base_port + i
        outbound = uri_to_outbound(cfg["raw"], tag)
        if not outbound:
            continue
        
        inbounds.append({
            "tag": in_tag,
            "port": port,
            "protocol": "http",
            "settings": {}
        })
        outbounds.append(outbound)
        rules.append({
            "inboundTag": [in_tag],
            "outboundTag": tag
        })
        valid_items.append((port, cfg))

    if not outbounds:
        return []

    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules}
    }

    config_path = f"/tmp/xray_batch_{base_port}.json"
    with open(config_path, "w") as f:
        json.dump(config, f)

    proc = subprocess.Popen([XRAY_BIN, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    verified_nodes = []

    def probe(port_and_cfg):
        local_port, c = port_and_cfg
        proxy_handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{local_port}"})
        opener = urllib.request.build_opener(proxy_handler)
        
        test_url = "http://cp.cloudflare.com/generate_204"

        try:
            t0 = time.perf_counter()
            req = urllib.request.Request(test_url, headers={"User-Agent": "curl/7.88.1"})
            resp = opener.open(req, timeout=3.0)
            if resp.status in [200, 204]:
                real_ping = max(1, int((time.perf_counter() - t0) * 1000))
                verified = dict(c)
                verified["ping_ms"] = real_ping
                verified["deep_verified"] = True
                return verified
        except Exception:
            pass
        return None

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(25, len(valid_items))) as executor:
            results = executor.map(probe, valid_items)
            for r in results:
                if r:
                    verified_nodes.append(r)
    finally:
        proc.terminate()
        proc.wait()
        try:
            os.remove(config_path)
        except OSError:
            pass

    return verified_nodes

def deep_check_nodes(candidate_nodes: list[dict], batch_size: int = 25, max_verified: int = 250) -> list[dict]:
    if not ensure_xray():
        logging.warning("Skipping deep Xray check (binary not available).")
        return candidate_nodes

    logging.info(f"Starting DEEP XRAY CORE verification on {len(candidate_nodes)} nodes (batch size {batch_size})...")
    verified = []
    
    # Process in batches
    for start_idx in range(0, len(candidate_nodes), batch_size):
        if len(verified) >= max_verified:
            logging.info(f"Reached target of {max_verified} deeply verified working nodes.")
            break
        
        batch = candidate_nodes[start_idx : start_idx + batch_size]
        base_port = 11100 + (start_idx % 500)
        batch_verified = test_xray_batch(batch, base_port=base_port)
        verified.extend(batch_verified)
        logging.info(f"Deep check progress: verified {len(verified)} working nodes so far (checked {start_idx + len(batch)} / {len(candidate_nodes)})...")

    logging.info(f"DEEP XRAY CHECK COMPLETE: Found {len(verified)} 100% WORKING NODES passing real HTTP traffic!")
    return verified
