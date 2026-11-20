import json
import base64
import re
from urllib.parse import urlparse, unquote, quote

BLOCKED_PORTS = {445, 135, 137, 138, 139, 25, 23}

def parse_config(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri:
        return None
    try:
        # VMess (JSON inside base64)
        if uri.startswith("vmess://"):
            b64_part = uri[8:]
            pad = len(b64_part) % 4
            if pad != 0:
                b64_part += "=" * (4 - pad)
            data_str = base64.b64decode(b64_part).decode("utf-8", errors="ignore")
            data = json.loads(data_str)
            host = data.get("add", "").strip()
            port = int(data.get("port", 0))
            if not host or not (1 <= port <= 65535) or port in BLOCKED_PORTS:
                return None
            return {
                "proto": "vmess",
                "host": host,
                "port": port,
                "raw": uri,
                "data": data,
                "remark": data.get("ps", "")
            }

        # Shadowsocks
        elif uri.startswith("ss://"):
            main = uri[5:]
            remark = ""
            if "#" in main:
                main, remark = main.split("#", 1)
            
            # SIP002 format: ss://base64(method:password)@host:port
            if "@" in main:
                auth, hostport = main.split("@", 1)
            else:
                # Legacy base64 format: ss://base64(method:password@host:port)
                pad = len(main) % 4
                if pad != 0:
                    main += "=" * (4 - pad)
                dec = base64.b64decode(main).decode("utf-8", errors="ignore")
                if "@" in dec:
                    auth, hostport = dec.split("@", 1)
                else:
                    return None
            
            if ":" in hostport:
                parts = hostport.split(":")
                host = parts[0].strip("[]")
                port = int(re.sub(r"\D", "", parts[1]) or 0)
                if not host or not (1 <= port <= 65535) or port in BLOCKED_PORTS:
                    return None
                return {
                    "proto": "ss",
                    "host": host,
                    "port": port,
                    "raw": uri,
                    "remark": unquote(remark)
                }

        # VLESS, Trojan, Hysteria2, Tuic
        else:
            match = re.match(r"^([a-z0-9]+)://(?:[^@]+@)?(\[[a-fA-F0-9:]+\]|[^:/?#]+):(\d+)(.*)$", uri)
            if match:
                proto, host, port_str, rest = match.groups()
                port = int(port_str)
                if not (1 <= port <= 65535) or port in BLOCKED_PORTS:
                    return None
                host = host.strip("[]")
                remark = ""
                if "#" in rest:
                    _, remark = rest.split("#", 1)
                
                # Check for reality/security in query
                is_reality = "security=reality" in rest
                sni = ""
                sni_match = re.search(r"sni=([^&]+)", rest)
                if sni_match:
                    sni = sni_match.group(1)

                return {
                    "proto": proto,
                    "host": host,
                    "port": port,
                    "raw": uri,
                    "remark": unquote(remark),
                    "is_reality": is_reality,
                    "sni": sni,
                    "rest": rest
                }
    except Exception:
        pass
    return None

def build_branded_uri(cfg: dict, new_remark: str) -> str:
    proto = cfg["proto"]
    try:
        if proto == "vmess":
            data = dict(cfg["data"])
            data["ps"] = new_remark
            enc = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
            return f"vmess://{enc}"
        
        elif proto == "ss":
            raw = cfg["raw"]
            if "#" in raw:
                base = raw.split("#", 1)[0]
            else:
                base = raw
            return f"{base}#{quote(new_remark)}"
        
        else:
            # vless, trojan, hy2, tuic
            raw = cfg["raw"]
            if "#" in raw:
                base = raw.split("#", 1)[0]
            else:
                base = raw
            return f"{base}#{quote(new_remark)}"
    except Exception:
        return cfg["raw"]

def deduplicate_configs(parsed_configs: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for cfg in parsed_configs:
        key = (cfg["host"].lower(), cfg["port"])
        if key not in seen:
            seen.add(key)
            unique.append(cfg)
    return unique
