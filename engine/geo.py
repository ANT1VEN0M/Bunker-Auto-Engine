import os
import socket
import logging
import urllib.request
import threading
import maxminddb

MMDB_URL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
MMDB_PATH = os.path.join(os.path.dirname(__file__), "Country.mmdb")

_reader = None
_dns_cache = {}
_lock = threading.Lock()

def init_geo():
    global _reader
    with _lock:
        if _reader is not None:
            return _reader
        if not os.path.exists(MMDB_PATH):
            logging.info("Downloading Country.mmdb for fast offline IP geolocation...")
            urllib.request.urlretrieve(MMDB_URL, MMDB_PATH)
            logging.info("Country.mmdb downloaded successfully.")
        _reader = maxminddb.open_database(MMDB_PATH)
        return _reader

def get_reader():
    if _reader is None:
        return init_geo()
    return _reader

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
        reader = get_reader()
        res = reader.get(ip)
        if res:
            iso = res.get("country", {}).get("iso_code")
            if iso:
                return iso.upper()
    except Exception:
        pass
    return "UN"

def get_flag_emoji(country_code: str) -> str:
    code = (country_code or "UN").upper()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(127397 + ord(c)) for c in code)
    return "🌐"
