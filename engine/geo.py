import os
import socket
import logging
import urllib.request
import threading
import maxminddb

COUNTRY_MMDB_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
COUNTRY_MMDB_PATH = os.path.join(os.path.dirname(__file__), "Country.mmdb")

ASN_MMDB_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-ASN.mmdb"
ASN_MMDB_PATH = os.path.join(os.path.dirname(__file__), "GeoLite2-ASN.mmdb")

WL_HOSTINGS_FILE = os.path.join(os.path.dirname(__file__), "wl_hostings.txt")
WL_HOSTINGS_URL = "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/wl_hostings.txt"

_country_reader = None
_asn_reader = None
_dns_cache = {}
_wl_hostings_cache = None
_lock = threading.Lock()

def init_geo():
    global _country_reader, _asn_reader
    with _lock:
        if _country_reader is None:
            if not os.path.exists(COUNTRY_MMDB_PATH):
                logging.info("Downloading Country.mmdb for fast offline IP geolocation...")
                try:
                    urllib.request.urlretrieve(COUNTRY_MMDB_URL, COUNTRY_MMDB_PATH)
                    logging.info("Country.mmdb downloaded successfully.")
                except Exception as e:
                    logging.warning(f"Failed to download Country.mmdb: {e}")
            if os.path.exists(COUNTRY_MMDB_PATH):
                _country_reader = maxminddb.open_database(COUNTRY_MMDB_PATH)

        if _asn_reader is None:
            if not os.path.exists(ASN_MMDB_PATH):
                logging.info("Downloading GeoLite2-ASN.mmdb for fast offline ASN resolution...")
                try:
                    urllib.request.urlretrieve(ASN_MMDB_URL, ASN_MMDB_PATH)
                    logging.info("GeoLite2-ASN.mmdb downloaded successfully.")
                except Exception as e:
                    logging.warning(f"Failed to download GeoLite2-ASN.mmdb: {e}")
            if os.path.exists(ASN_MMDB_PATH):
                _asn_reader = maxminddb.open_database(ASN_MMDB_PATH)

        return _country_reader, _asn_reader

def get_wl_hostings() -> dict[int, str]:
    global _wl_hostings_cache
    with _lock:
        if _wl_hostings_cache is not None:
            return _wl_hostings_cache
        
        hostings = {}
        if not os.path.exists(WL_HOSTINGS_FILE):
            try:
                logging.info("Fetching wl_hostings.txt from remote...")
                urllib.request.urlretrieve(WL_HOSTINGS_URL, WL_HOSTINGS_FILE)
            except Exception as e:
                logging.warning(f"Failed to fetch wl_hostings.txt: {e}")

        if os.path.exists(WL_HOSTINGS_FILE):
            try:
                with open(WL_HOSTINGS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t") if "\t" in line else line.split()
                        if parts and parts[0].isdigit():
                            asn = int(parts[0])
                            name = " ".join(parts[1:]) if len(parts) > 1 else f"AS{asn}"
                            hostings[asn] = name
            except Exception as e:
                logging.warning(f"Error reading wl_hostings.txt: {e}")

        _wl_hostings_cache = hostings
        return _wl_hostings_cache

def resolve_host_to_ip(host: str) -> str | None:
    host = host.strip("[]").strip()
    if not host:
        return None
    
    with _lock:
        if host in _dns_cache:
            return _dns_cache[host]
    
    # Check if host is already an IPv4
    try:
        socket.inet_aton(host)
        with _lock:
            _dns_cache[host] = host
        return host
    except socket.error:
        pass
    
    # IPv6 check
    try:
        socket.inet_pton(socket.AF_INET6, host)
        with _lock:
            _dns_cache[host] = host
        return host
    except (socket.error, AttributeError):
        pass
    
    # Resolve domain via DNS
    try:
        ip = socket.gethostbyname(host)
        with _lock:
            _dns_cache[host] = ip
        return ip
    except Exception:
        with _lock:
            _dns_cache[host] = None
        return None

def get_country_code(ip_or_host: str) -> str:
    ip = resolve_host_to_ip(ip_or_host)
    if not ip:
        return "UN"
    
    try:
        init_geo()
        if _country_reader:
            res = _country_reader.get(ip)
            if res:
                iso = res.get("country", {}).get("iso_code")
                if iso:
                    return iso.upper()
    except Exception:
        pass
    return "UN"

def get_asn_info(ip_or_host: str) -> tuple[int | None, str | None]:
    ip = resolve_host_to_ip(ip_or_host)
    if not ip:
        return None, None
    try:
        init_geo()
        if _asn_reader:
            res = _asn_reader.get(ip)
            if res:
                asn = res.get("autonomous_system_number")
                org = res.get("autonomous_system_organization")
                return asn, org
    except Exception:
        pass
    return None, None

def is_russian_wl_hosting(ip_or_host: str, asn: int | None = None) -> tuple[bool, str | None]:
    if asn is None:
        asn, _ = get_asn_info(ip_or_host)
    if not asn:
        return False, None
    
    wl_map = get_wl_hostings()
    if asn in wl_map:
        return True, wl_map[asn]
    return False, None

def get_flag_emoji(country_code: str) -> str:
    code = (country_code or "UN").upper()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(127397 + ord(c)) for c in code)
    return "🌐"
