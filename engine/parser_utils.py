import json
import base64
import re
from pathlib import Path
from urllib.parse import urlparse, unquote, quote
from .cleaner import clean_and_parse_uri, build_canonical_uri

BLOCKED_PORTS = {445, 135, 137, 138, 139, 25, 23}
DUMMY_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}

_VERIFIED_RU_SET = set()
def _init_verified_ru_set():
    global _VERIFIED_RU_SET
    if _VERIFIED_RU_SET:
        return
    vf_path = Path(__file__).resolve().parent / "verified_ru_nodes.txt"
    if vf_path.exists():
        try:
            with open(vf_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        base = line.split("#", 1)[0].strip()
                        _VERIFIED_RU_SET.add(base)
                        m = re.search(r"@([^:/?#]+):(\d+)", line)
                        if m:
                            _VERIFIED_RU_SET.add(f"{m.group(1)}:{m.group(2)}")
        except Exception:
            pass

def parse_config(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri or "00000000-0000" in uri:
        return None
    try:
        # 1. Custom & Emergency Tunnel Protocols (WDTT / qWDTT)
        if uri.startswith("wdtt://") or uri.startswith("qwdtt://"):
            from engine.npv_parser import decode_wdtt
            w_res = decode_wdtt(uri)
            if w_res and w_res.get("host") and not (w_res["host"].lower() in DUMMY_HOSTS):
                return {
                    "proto": w_res["proto"],
                    "host": w_res["host"].lower(),
                    "port": int(w_res["port"]),
                    "raw": uri,
                    "remark": w_res.get("name", ""),
                    "fingerprint": f"wdtt:{w_res['host']}:{w_res['port']}"
                }

        # 2. OpenVPN URI
        elif uri.startswith("ovpn://"):
            main = uri[7:]
            remark = ""
            if "#" in main:
                main, remark = main.split("#", 1)
            pad = len(main) % 4
            if pad != 0:
                main += "=" * (4 - pad)
            dec = base64.b64decode(main).decode("utf-8", errors="ignore")
            remote_m = re.search(r"^\s*remote\s+([^\s]+)(?:\s+(\d+))?", dec, re.MULTILINE | re.IGNORECASE)
            if remote_m:
                host = remote_m.group(1).strip().lower()
                port = int(remote_m.group(2) or 1194)
                if not host or host in DUMMY_HOSTS or not (1 <= port <= 65535) or port in BLOCKED_PORTS:
                    return None
                return {
                    "proto": "ovpn",
                    "host": host,
                    "port": port,
                    "raw": uri,
                    "remark": unquote(remark),
                    "fingerprint": f"ovpn:{host}:{port}"
                }

        # 3. Standard & Modern Proxies via Cleaner (VLESS, VMess, Trojan, SS, Hysteria2)
        _init_verified_ru_set()
        cleaned = clean_and_parse_uri(uri)
        if cleaned:
            base = uri.split("#", 1)[0].strip()
            ep = f"{cleaned.get('host')}:{cleaned.get('port')}"
            if base in _VERIFIED_RU_SET or ep in _VERIFIED_RU_SET:
                cleaned["is_ru_verified"] = True
                cleaned["deep_verified"] = True
            return cleaned

    except Exception:
        pass
    return None

def build_branded_uri(cfg: dict, new_remark: str) -> str:
    # If we have the parsed Node from cleaner, build canonical branded URI
    if "node" in cfg and cfg["node"]:
        return build_canonical_uri(cfg["node"], new_remark)

    proto = cfg.get("proto", "")
    try:
        if proto == "vmess":
            data = dict(cfg.get("data", {}))
            data["ps"] = new_remark
            enc = base64.b64encode(json.dumps(data, separators=(",", ":")).encode("utf-8")).decode("utf-8")
            return f"vmess://{enc}"
        else:
            raw = cfg.get("raw", "")
            base = raw.split("#", 1)[0] if "#" in raw else raw
            return f"{base}#{quote(new_remark)}"
    except Exception:
        return cfg.get("raw", "")

def deduplicate_configs(parsed_configs: list[dict]) -> list[dict]:
    """Smart deduplication based on Blake2b node fingerprint and host:port."""
    seen_fp = set()
    unique = []
    for cfg in parsed_configs:
        fp = cfg.get("fingerprint") or f"{cfg.get('proto')}:{cfg.get('host')}:{cfg.get('port')}"
        if fp not in seen_fp:
            seen_fp.add(fp)
            unique.append(cfg)
    return unique
