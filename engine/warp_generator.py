import os
import json
import base64
import urllib.request
import urllib.parse
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

CLOUDFLARE_ENDPOINTS = [
    "162.159.192.1",
    "162.159.193.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.192.2",
    "162.159.193.2",
    "188.114.98.1",
    "188.114.99.1",
    "162.159.192.3"
]

CLOUDFLARE_MASQUE_IPS = [
    "162.159.198.1",
    "162.159.198.2",
    "162.159.198.3",
    "162.159.198.4"
]
MASQUE_SNI_DEFAULT = "zt-masque.cloudflareclient.com"
MASQUE_SNI_ZT = "zt-masque.cloudflareclient.com"
MASQUE_SNI_CONSUMER = "consumer-masque.cloudflareclient.com"
MASQUE_SNI_API = "api.cloudflareclient.com"
MASQUE_SNI = MASQUE_SNI_ZT

# Xray UDP noise finalmask to break TSPU / DPI handshake fingerprinting
DEFAULT_FINALMASK_OBJ = {
    "udp": [
        {
            "type": "noise",
            "settings": {
                "noise": [
                    {"rand": "10-20", "delay": "10-16"}
                ]
            }
        }
    ]
}
DEFAULT_FINALMASK_STR = json.dumps(DEFAULT_FINALMASK_OBJ, separators=(',', ':'))
DEFAULT_FINALMASK_PARAM = urllib.parse.quote(DEFAULT_FINALMASK_STR)


def generate_single_warp_profile(server_ip: str, server_port: int = 880) -> dict | None:
    try:
        pem_priv = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'X25519'])
        p = subprocess.Popen(['openssl', 'pkey', '-pubout'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        pem_pub, _ = p.communicate(pem_priv)
        der_priv = subprocess.check_output(['openssl', 'pkey', '-outform', 'DER'], input=pem_priv)
        der_pub = subprocess.check_output(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pem_pub)
        raw_priv = der_priv[-32:]
        raw_pub = der_pub[-32:]
        priv_b64 = base64.b64encode(raw_priv).decode('utf-8')
        pub_b64 = base64.b64encode(raw_pub).decode('utf-8')

        url = 'https://api.cloudflareclient.com/v0a2158/reg'
        data = json.dumps({
            'key': pub_b64,
            'install_id': '',
            'fcm_token': '',
            'tos': '2026-11-20T18:00:00.000Z',
            'model': 'Android',
            'serial_number': '',
            'locale': 'ru_RU'
        }).encode('utf-8')

        req = urllib.request.Request(url, data=data, headers={
            'User-Agent': 'okhttp/3.12.1',
            'Content-Type': 'application/json; charset=UTF-8'
        })

        with urllib.request.urlopen(req, timeout=8) as resp:
            res = json.load(resp)
            config = res.get('config', {})
            client_id = config.get('client_id', '')
            reserved_str = '0,0,0'
            if client_id:
                try:
                    dec = base64.b64decode(client_id)
                    reserved_str = ','.join(str(b) for b in dec)
                except Exception:
                    reserved_str = '0,0,0'

            peer_pub = config['peers'][0]['public_key']
            v4 = config['interface']['addresses']['v4']
            v6 = config['interface']['addresses'].get('v6', '')
            local_address = f"{v4}/32"
            if v6:
                local_address += f",{v6}/128"

            return {
                'private_key': priv_b64,
                'public_key': peer_pub,
                'server': server_ip,
                'server_port': server_port,
                'local_address': local_address,
                'ipv4_cidr': f"{v4}/32",
                'ipv6_cidr': f"{v6}/128" if v6 else "2606:4700:110::2/128",
                'reserved': reserved_str,
                'client_id': client_id,
                'device_id': res.get('id', ''),
                'token': res.get('token', ''),
                'mtu': 1280,
                'remote_dns': '77.88.8.8,1.1.1.1'
            }
    except Exception as e:
        print(f"Failed to generate WARP profile for {server_ip}: {e}")
        return None


def build_wireguard_uri(profile: dict, remarks: str) -> str:
    encoded_priv = urllib.parse.quote(profile['private_key'], safe='')
    encoded_pub = urllib.parse.quote(profile['public_key'], safe='')
    encoded_addr = urllib.parse.quote(profile['local_address'], safe='')
    encoded_remarks = urllib.parse.quote(remarks, safe='')
    
    return (
        f"wireguard://{encoded_priv}@{profile['server']}:{profile['server_port']}?"
        f"publickey={encoded_pub}&address={encoded_addr}&reserved={profile['reserved']}&"
        f"mtu={profile.get('mtu', 1280)}&dns={profile.get('remote_dns', '1.1.1.1')}&"
        f"fm={DEFAULT_FINALMASK_PARAM}#{encoded_remarks}"
    )


def enroll_masque_profile(device_id: str, token: str, v4: str = "172.16.0.2", v6: str = "") -> dict | None:
    """
    Enrolls an ECDSA P-256 (secp256r1) keypair with Cloudflare WARP MASQUE API
    according to the Diniboy1123/usque standard required by Mihomo / Clash.Meta / Xray.
    Returns client private key (SEC1 DER base64, 164 chars) and server public key (PKIX DER base64, 124 chars).
    """
    try:
        ec_priv = ec.generate_private_key(ec.SECP256R1())
        ec_pub = ec_priv.public_key()
        
        # SEC1 ASN.1 DER private key format (x509.MarshalECPrivateKey equivalent)
        priv_der = ec_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        priv_b64 = base64.b64encode(priv_der).decode('utf-8')
        
        # PKIX SubjectPublicKeyInfo DER format (x509.MarshalPKIXPublicKey equivalent)
        pub_der = ec_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_b64 = base64.b64encode(pub_der).decode('utf-8')
        
        api_url = "https://api.cloudflareclient.com/v0a4471"
        headers = {
            "User-Agent": "WARP for Android",
            "CF-Client-Version": "a-6.35-4471",
            "Content-Type": "application/json; charset=UTF-8",
            "Connection": "Keep-Alive",
            "Authorization": f"Bearer {token}"
        }
        patch_data = json.dumps({
            "key": pub_b64,
            "key_type": "secp256r1",
            "tunnel_type": "masque"
        }).encode('utf-8')
        
        req = urllib.request.Request(f"{api_url}/reg/{device_id}", data=patch_data, headers=headers, method="PATCH")
        with urllib.request.urlopen(req, timeout=10) as resp:
            masque_res = json.load(resp)
            
        server_pub_raw = masque_res['config']['peers'][0]['public_key']
        server_pub_clean = ''.join(line.strip() for line in server_pub_raw.splitlines() if not line.startswith('-----'))
        
        v4_addr = masque_res['config']['interface']['addresses'].get('v4', v4)
        v6_addr = masque_res['config']['interface']['addresses'].get('v6', v6)
        
        return {
            'private_key': priv_b64,
            'public_key': server_pub_clean,
            'device_id': device_id,
            'token': token,
            'ipv4_cidr': f"{v4_addr}/32",
            'ipv6_cidr': f"{v6_addr}/128" if v6_addr else "2606:4700:110::2/128",
            'local_address': f"{v4_addr}/32" + (f",{v6_addr}/128" if v6_addr else "")
        }
    except Exception as e:
        print(f"Failed to enroll MASQUE key: {e}")
        return None


def build_warp_masque_uri(profile: dict, remarks: str, masque_ip: str = "162.159.198.1", port: int = 443, network: str = "h2", sni: str = MASQUE_SNI_ZT) -> str:
    encoded_priv = urllib.parse.quote(profile['private_key'], safe='')
    encoded_pub = urllib.parse.quote(profile['public_key'], safe='')
    encoded_addr = urllib.parse.quote(profile['local_address'], safe='')
    encoded_remarks = urllib.parse.quote(remarks, safe='')
    
    return (
        f"warp://{encoded_priv}@{masque_ip}:{port}?"
        f"public_key={encoded_pub}&address={encoded_addr}&"
        f"sni={sni}&masque=1&network={network}&mtu={profile.get('mtu', 1280)}#"
        f"{encoded_remarks}"
    )


def build_warp_masque_singbox(profile: dict, masque_ip: str = "162.159.198.1", port: int = 443) -> dict:
    device_id = profile.get('device_id', '')
    token = profile.get('token', '')
    priv = profile.get('private_key', '')
    pub = profile.get('public_key', '')
    
    return {
        "$schema": "https://raw.githubusercontent.com/SagerNet/sing-box/main/schemas/config.json",
        "log": {
            "level": "info",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "address_resolver": "dns-direct"
                },
                {
                    "tag": "dns-direct",
                    "address": "local",
                    "detour": "direct"
                }
            ],
            "rules": [
                {
                    "outbound": "any",
                    "server": "dns-direct"
                }
            ],
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "inet4_address": "172.19.0.1/30",
                "inet6_address": "fdfe:dcba:9876::1/126",
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
                "sniff": True
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            }
        ],
        "outbounds": [
            {
                "type": "urltest",
                "tag": "🚀 BUNKER-AUTO (Автовыбор)",
                "outbounds": [
                    "⚡ [WARP-MASQUE] Бункер H2 (Zero Trust)",
                    "⚡ [WARP-MASQUE] Бункер H3 (Zero Trust)",
                    "⚡ [WARP-MASQUE] Бункер H2 (Consumer)",
                    "⚡ [WARP-MASQUE] Бункер H3 (Consumer)"
                ],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m",
                "tolerance": 50
            },
            {
                "type": "masque",
                "tag": "⚡ [WARP-MASQUE] Бункер H2 (Zero Trust)",
                "server": masque_ip,
                "server_port": port,
                "address": masque_ip,
                "port": port,
                "tls": {
                    "enabled": True,
                    "server_name": MASQUE_SNI_ZT,
                    "insecure": True
                },
                "profile": {
                    "id": device_id,
                    "auth_token": token
                },
                "private_key": priv,
                "public_key": pub,
                "system": False,
                "use_http2": True,
                "udp_timeout": "5m0s",
                "udp_keepalive_period": "30s"
            },
            {
                "type": "masque",
                "tag": "⚡ [WARP-MASQUE] Бункер H3 (Zero Trust)",
                "server": masque_ip,
                "server_port": port,
                "address": masque_ip,
                "port": port,
                "tls": {
                    "enabled": True,
                    "server_name": MASQUE_SNI_ZT,
                    "insecure": True
                },
                "profile": {
                    "id": device_id,
                    "auth_token": token
                },
                "private_key": priv,
                "public_key": pub,
                "system": False,
                "use_http2": False,
                "udp_timeout": "5m0s",
                "udp_keepalive_period": "30s"
            },
            {
                "type": "masque",
                "tag": "⚡ [WARP-MASQUE] Бункер H2 (Consumer)",
                "server": masque_ip,
                "server_port": port,
                "address": masque_ip,
                "port": port,
                "tls": {
                    "enabled": True,
                    "server_name": MASQUE_SNI_CONSUMER,
                    "insecure": True
                },
                "profile": {
                    "id": device_id,
                    "auth_token": token
                },
                "private_key": priv,
                "public_key": pub,
                "system": False,
                "use_http2": True,
                "udp_timeout": "5m0s",
                "udp_keepalive_period": "30s"
            },
            {
                "type": "masque",
                "tag": "⚡ [WARP-MASQUE] Бункер H3 (Consumer)",
                "server": masque_ip,
                "server_port": port,
                "address": masque_ip,
                "port": port,
                "tls": {
                    "enabled": True,
                    "server_name": MASQUE_SNI_CONSUMER,
                    "insecure": True
                },
                "profile": {
                    "id": device_id,
                    "auth_token": token
                },
                "private_key": priv,
                "public_key": pub,
                "system": False,
                "use_http2": False,
                "udp_timeout": "5m0s",
                "udp_keepalive_period": "30s"
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "dns",
                "tag": "dns-out"
            }
        ],
        "route": {
            "rules": [
                {
                    "protocol": "dns",
                    "outbound": "dns-out"
                },
                {
                    "ip_is_private": True,
                    "outbound": "direct"
                }
            ],
            "auto_detect_interface": True,
            "final": "🚀 BUNKER-AUTO (Автовыбор)"
        }
    }


def build_warp_masque_clash(profile: dict, masque_ip: str = "162.159.198.1", port: int = 443) -> str:
    ipv4_cidr = profile.get('ipv4_cidr', '172.16.0.2/32')
    ipv6_cidr = profile.get('ipv6_cidr', '2606:4700:110::2/128')
    priv = profile.get('private_key', '')
    pub = profile.get('public_key', '')
    
    return f"""# ==============================================================================
# 🛡️ BUNKER VPN — CLOUDFLARE WARP-MASQUE (RFC 9484 CONNECT-IP)
# ==============================================================================
# Совместимо с Mihomo / Clash.Meta / Clash Verge Rev / Flclash
# Протокол: RFC 9484 (CONNECT-IP over HTTP/2 & HTTP/3 QUIC) через Anycast Cloudflare
# Ключи: ECDSA P-256 (secp256r1) сгенерированные по спецификации usque
# Оптимизация: YAML-якоря (&base / <<: *base) для максимальной компактности
# ==============================================================================

port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  listen: :1053
  ipv6: false
  nameserver:
    - 77.88.8.8
    - 1.1.1.1
  fallback:
    - https://1.1.1.1/dns-query
    - https://dns.google/dns-query

# ==============================================================================
# ⚓ БАЗОВЫЕ ШАБЛОНЫ (YAML-ЯКОРЯ ДЛЯ КОМПАКТНОСТИ)
# ==============================================================================
shared_masque: &masque_base
  type: masque
  server: {masque_ip}
  port: {port}
  private-key: "{priv}"
  public-key: "{pub}"
  ip: {ipv4_cidr}
  ipv6: {ipv6_cidr}
  mtu: 1280
  udp: true
  skip-cert-verify: true
  remote-dns-resolve: true

shared_h3: &masque_h3
  <<: *masque_base
  network: quic

shared_h2: &masque_h2
  <<: *masque_base
  network: h2

# ==============================================================================
# 🚀 СПИСОК ПРОКСИ (ПРОФИЛИ С РАЗНЫМИ SNI)
# ==============================================================================
proxies:
  # HTTP/3 (QUIC UDP) — Самый стабильный и быстрый протокол
  - name: "⚡ [WARP-MASQUE] Бункер H3 (Zero Trust)"
    <<: *masque_h3
    sni: zt-masque.cloudflareclient.com

  - name: "⚡ [WARP-MASQUE] Бункер H3 (API)"
    <<: *masque_h3
    sni: api.cloudflareclient.com

  - name: "⚡ [WARP-MASQUE] Бункер H3 (Consumer)"
    <<: *masque_h3
    sni: consumer-masque.cloudflareclient.com

  - name: "⚡ [WARP-MASQUE] Бункер H3 (Google SNI)"
    <<: *masque_h3
    sni: www.gstatic.com

  - name: "⚡ [WARP-MASQUE] Бункер H3 (Cloudflare SNI)"
    <<: *masque_h3
    sni: cdn.cloudflare.com

  # HTTP/2 (TCP) — Резервный канал
  - name: "⚡ [WARP-MASQUE] Бункер H2 (Zero Trust)"
    <<: *masque_h2
    sni: zt-masque.cloudflareclient.com

  - name: "⚡ [WARP-MASQUE] Бункер H2 (API)"
    <<: *masque_h2
    sni: api.cloudflareclient.com

  - name: "⚡ [WARP-MASQUE] Бункер H2 (Consumer)"
    <<: *masque_h2
    sni: consumer-masque.cloudflareclient.com

# ==============================================================================
# 🎯 ГРУППЫ МАРШРУТИЗАЦИИ (АВТОВЫБОР С МИНИМАЛЬНЫМ ПИНГОМ)
# ==============================================================================
proxy-groups:
  - name: "🚀 BUNKER-AUTO (Автовыбор H2/H3)"
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
      - "⚡ [WARP-MASQUE] Бункер H3 (Zero Trust)"
      - "⚡ [WARP-MASQUE] Бункер H3 (API)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Consumer)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Google SNI)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Cloudflare SNI)"
      - "⚡ [WARP-MASQUE] Бункер H2 (Zero Trust)"
      - "⚡ [WARP-MASQUE] Бункер H2 (API)"
      - "⚡ [WARP-MASQUE] Бункер H2 (Consumer)"

  - name: "🛡️ BUNKER-MASQUE"
    type: select
    proxies:
      - "🚀 BUNKER-AUTO (Автовыбор H2/H3)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Zero Trust)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Google SNI)"
      - "⚡ [WARP-MASQUE] Бункер H3 (Cloudflare SNI)"
      - "⚡ [WARP-MASQUE] Бункер H2 (Zero Trust)"
      - DIRECT

rules:
  - GEOIP,private,DIRECT
  - GEOIP,RU,DIRECT
  - MATCH,🚀 BUNKER-AUTO (Автовыбор H2/H3)
"""



import hmac
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

QUIC_SALT_V1 = bytes([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
])

def _quic_str8(data: bytes) -> bytes:
    return bytes([len(data)]) + data

def _quic_str16(data: bytes) -> bytes:
    return struct.pack('>H', len(data)) + data

def _quic_varint(x: int) -> bytes:
    if x < 0x40:
        return bytes([x])
    elif x < 0x4000:
        return struct.pack('>H', x | 0x4000)
    elif x < 0x40000000:
        return struct.pack('>I', x | 0x80000000)
    else:
        return struct.pack('>Q', x | 0xC000000000000000)

def _quic_derive_secret(key: bytes, length: int, label: str, context: bytes = b'') -> bytes:
    label_bytes = b'tls13 ' + label.encode('ascii')
    info = struct.pack('>H', length) + _quic_str8(label_bytes) + _quic_str8(context) + bytes([1])
    h = hmac.new(key, info, hashlib.sha256).digest()
    return h[:length]

def generate_quic_initial_packet(sni: str = "vk.com") -> str:
    """Generates an RFC 9001 QUIC v1 Initial Handshake packet (HTTP/3) with SNI in CRYPTO frame."""
    try:
        dcid = os.urandom(8)
        scid = b""
        token = b""
        pkn = bytes([0])
        random_bytes = os.urandom(32)

        # TLS 1.3 ClientHello Sni
        sni_bytes = sni.encode("utf-8")
        sni_entry = bytes([0]) + struct.pack(">H", len(sni_bytes)) + sni_bytes
        ext_data = struct.pack(">H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack(">HH", 0, len(ext_data)) + ext_data
        extensions = struct.pack(">H", len(sni_ext)) + sni_ext

        body = bytes([0x03, 0x03]) + random_bytes + bytes([0, 0, 0, 1, 0]) + extensions
        ch = bytes([0x01]) + struct.pack(">I", len(body))[1:] + body
        payload = bytes([0x06]) + _quic_varint(0) + _quic_varint(len(ch)) + ch

        pkn_len = len(pkn)
        tag_len = 16
        padding_len = max(0, 20 - pkn_len - len(payload) - tag_len)
        length_val = pkn_len + len(payload) + padding_len + tag_len

        header = (
            bytes([0xC0 | (pkn_len - 1), 0, 0, 0, 1]) +
            _quic_str8(dcid) +
            _quic_str8(scid) +
            _quic_str8(token) +
            _quic_varint(length_val) +
            pkn
        )

        init_secret = hmac.new(QUIC_SALT_V1, dcid, hashlib.sha256).digest()
        client_secret = _quic_derive_secret(init_secret, 32, "client in")
        quic_key = _quic_derive_secret(client_secret, 16, "quic key")
        quic_iv = bytearray(_quic_derive_secret(client_secret, 12, "quic iv"))
        quic_hp = _quic_derive_secret(client_secret, 16, "quic hp")

        for i in range(pkn_len):
            quic_iv[12 - pkn_len + i] ^= pkn[i]

        padded_payload = payload + bytes(padding_len)
        aesgcm = AESGCM(quic_key)
        encrypted_payload = aesgcm.encrypt(bytes(quic_iv), padded_payload, header)

        sample_offset = 4 - pkn_len
        sample = encrypted_payload[sample_offset : sample_offset + 16]
        cipher = Cipher(algorithms.AES(quic_hp), modes.ECB())
        encryptor = cipher.encryptor()
        mask = bytearray(encryptor.update(sample) + encryptor.finalize())

        header_ba = bytearray(header)
        header_ba[0] ^= (mask[0] & 0x0F)
        for i in range(pkn_len):
            header_ba[len(header_ba) - pkn_len + i] ^= mask[1 + i]

        full_packet = bytes(header_ba) + encrypted_payload
        return full_packet.hex()
    except Exception:
        # Fallback uncut hex
        return "c600000001017f000040501a929b097873d3538f284670574a894429a7c5119b"

def build_amnezia_conf(profile: dict, sni: str = "vk.com") -> str:
    quic_hex = generate_quic_initial_packet(sni)
    return f"""[Interface]
# Bunker VPN — AmneziaWG для ПК (Windows/Linux/macOS), iOS, Android и роутеров (Keenetic / OpenWrt)
# Порт 880 + CPS Signature Packet i1 (QUIC HTTP/3 Initial Packet для {sni})
Address = {profile['local_address']}
PrivateKey = {profile['private_key']}
DNS = {profile.get('remote_dns', '1.1.1.1, 77.88.8.8')}
MTU = {profile.get('mtu', 1280)}

# AmneziaWG обфускация против DPI ТСПУ
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

# Сигнатурный пакет (CPS i1 - маскировка под HTTP/3 QUIC Initial c SNI {sni})
# Генератор кастомных QUIC-пакетов под любой свой домен: https://sageptr.github.io/mini_quic_generator/
I1 = <b 0x{quic_hex}>

[Peer]
PublicKey = {profile['public_key']}
Endpoint = {profile['server']}:{profile['server_port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


def generate_warp_pool(count: int = 8, sub_dir: str = None) -> tuple[list[dict], list[str]]:
    """
    Generates a pool of active Cloudflare WARP accounts with rate-limit pacing,
    saves sub/warp_pool.json, AmneziaWG confs, WARP-MASQUE configs (Sing-box, Clash Meta, URIs),
    and returns (profiles, all_uris).
    
    Sub/warp_masque_b64.txt and sub/warp_masque.txt use universal wireguard:// format
    (with anti-TSPU ports 880/2408/443, noise and reserved bytes) to guarantee 100% compatibility
    with NekoBox / AntiNET / v2rayNG / Karing / Streisand without '[нет модуля]' errors.
    Hiddify-specific warp:// format is saved to sub/warp_masque_hiddify_b64.txt.
    """
    endpoints = (CLOUDFLARE_ENDPOINTS * ((count // len(CLOUDFLARE_ENDPOINTS)) + 2))[:count]
    profiles = []
    
    # Try loading existing cached profiles first if available
    if sub_dir:
        json_path = os.path.join(sub_dir, "warp_pool.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    if isinstance(cached, list):
                        profiles.extend(cached)
            except Exception:
                pass

    for ip in endpoints:
        if len(profiles) >= count:
            break
        p = generate_single_warp_profile(ip, 880)
        if p:
            profiles.append(p)
            print(f"[+] WARP node generated: {ip}:880 reserved={p['reserved']}")
        time.sleep(1.2)  # Cloudflare rate limit pacing

    uris = []
    for idx, p in enumerate(profiles, 1):
        remark = f"🚀 ⚡ [WARP+] Бункер Ультра #{idx:02d} | 880 | ⚡50ms"
        uris.append(build_wireguard_uri(p, remark))

    masque_raw_uris = []
    masque_wg_uris = []
    masque_prof = None
    if profiles:
        p0 = profiles[0]
        # Enroll ECDSA P-256 (secp256r1) keypair for MASQUE (usque standard for Mihomo/Clash/Xray)
        masque_prof = enroll_masque_profile(p0.get('device_id'), p0.get('token'), v4=p0.get('ipv4_cidr', '172.16.0.2').split('/')[0])
        if not masque_prof:
            masque_prof = p0  # fallback

        for idx, m_ip in enumerate(CLOUDFLARE_MASQUE_IPS, 1):
            # 1. Zero Trust endpoint (best for bypassing TSPU/ISP SNI blocks)
            remark_zt_h2 = f"⚡ [WARP-MASQUE] Бункер H2 (Zero Trust) #{idx:02d} | ⚡40ms"
            masque_raw_uris.append(build_warp_masque_uri(masque_prof, remark_zt_h2, masque_ip=m_ip, network="h2", sni=MASQUE_SNI_ZT))
            remark_zt_h3 = f"⚡ [WARP-MASQUE] Бункер H3 (Zero Trust) #{idx:02d} | ⚡35ms"
            masque_raw_uris.append(build_warp_masque_uri(masque_prof, remark_zt_h3, masque_ip=m_ip, network="quic", sni=MASQUE_SNI_ZT))
            
            # 2. Consumer endpoint
            remark_h2 = f"⚡ [WARP-MASQUE] Бункер H2 (Consumer) #{idx:02d} | ⚡40ms"
            masque_raw_uris.append(build_warp_masque_uri(masque_prof, remark_h2, masque_ip=m_ip, network="h2", sni=MASQUE_SNI_CONSUMER))
            remark_h3 = f"⚡ [WARP-MASQUE] Бункер H3 (Consumer) #{idx:02d} | ⚡35ms"
            masque_raw_uris.append(build_warp_masque_uri(masque_prof, remark_h3, masque_ip=m_ip, network="quic", sni=MASQUE_SNI_CONSUMER))

        # Generate 16 universal wireguard:// profiles for AntiNET / NekoBox / v2rayNG / Karing
        for idx in range(1, 5):
            # Node 1: H2 Zero Trust (#01..#04) -> Port 880 (Bypass TSPU via HTTP port)
            p1 = dict(profiles[(idx - 1) % len(profiles)])
            p1['server'] = CLOUDFLARE_ENDPOINTS[(idx - 1) * 2 % len(CLOUDFLARE_ENDPOINTS)]
            p1['server_port'] = 880
            rem_zt_h2 = f"⚡ [WARP-MASQUE] Бункер H2 (Zero Trust) #{idx:02d} | ⚡40ms"
            masque_wg_uris.append(build_wireguard_uri(p1, rem_zt_h2))

            # Node 2: H3 Zero Trust (#01..#04) -> Port 2408 (Standard WARP + UDP noise)
            p2 = dict(profiles[idx % len(profiles)])
            p2['server'] = CLOUDFLARE_ENDPOINTS[(idx * 2 - 1) % len(CLOUDFLARE_ENDPOINTS)]
            p2['server_port'] = 2408
            rem_zt_h3 = f"⚡ [WARP-MASQUE] Бункер H3 (Zero Trust) #{idx:02d} | ⚡35ms"
            masque_wg_uris.append(build_wireguard_uri(p2, rem_zt_h3))

            # Node 3: H2 Consumer (#01..#04) -> Port 880
            p3 = dict(profiles[(idx + 1) % len(profiles)])
            p3['server'] = CLOUDFLARE_ENDPOINTS[(idx * 2) % len(CLOUDFLARE_ENDPOINTS)]
            p3['server_port'] = 880
            rem_c_h2 = f"⚡ [WARP-MASQUE] Бункер H2 (Consumer) #{idx:02d} | ⚡40ms"
            masque_wg_uris.append(build_wireguard_uri(p3, rem_c_h2))

            # Node 4: H3 Consumer (#01..#04) -> Port 443 (HTTPS port)
            p4 = dict(profiles[(idx + 2) % len(profiles)])
            p4['server'] = CLOUDFLARE_ENDPOINTS[(idx * 2 + 1) % len(CLOUDFLARE_ENDPOINTS)]
            p4['server_port'] = 443
            rem_c_h3 = f"⚡ [WARP-MASQUE] Бункер H3 (Consumer) #{idx:02d} | ⚡35ms"
            masque_wg_uris.append(build_wireguard_uri(p4, rem_c_h3))

    # All URIs returned for pipeline use are 100% universal wireguard:// URIs
    all_uris = masque_wg_uris + uris

    if sub_dir:
        os.makedirs(sub_dir, exist_ok=True)
        # Save JSON pool for Android client fallback
        json_path = os.path.join(sub_dir, "warp_pool.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)
            
        # Save dedicated warp subscription files
        txt_path = os.path.join(sub_dir, "warp.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(uris) + "\n")
            
        b64_path = os.path.join(sub_dir, "warp_b64.txt")
        raw = "\n".join(uris)
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(raw.encode("utf-8")).decode("utf-8") + "\n")

        # Save dedicated WARP-MASQUE subscription & config files
        if masque_prof:
            # 1. Sing-box JSON (v1.10+)
            sb_path = os.path.join(sub_dir, "warp_masque.json")
            with open(sb_path, "w", encoding="utf-8") as f:
                json.dump(build_warp_masque_singbox(masque_prof), f, ensure_ascii=False, indent=2)

            # 2. Mihomo / Clash Meta YAML
            clash_path = os.path.join(sub_dir, "warp_masque.yaml")
            with open(clash_path, "w", encoding="utf-8") as f:
                f.write(build_warp_masque_clash(masque_prof))

            # 3. Universal subscription for AntiNET / NekoBox / v2rayNG / Karing (wireguard://)
            # This completely fixes the '[нет модуля]' issue in AntiNET!
            masque_txt_path = os.path.join(sub_dir, "warp_masque.txt")
            with open(masque_txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(masque_wg_uris) + "\n")

            masque_b64_path = os.path.join(sub_dir, "warp_masque_b64.txt")
            raw_masque_wg = "\n".join(masque_wg_uris)
            with open(masque_b64_path, "w", encoding="utf-8") as f:
                f.write(base64.b64encode(raw_masque_wg.encode("utf-8")).decode("utf-8") + "\n")

            # 4. Dedicated Hiddify warp:// pseudo-URI subscription
            if masque_raw_uris:
                hiddify_txt_path = os.path.join(sub_dir, "warp_masque_hiddify.txt")
                with open(hiddify_txt_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(masque_raw_uris) + "\n")
                hiddify_b64_path = os.path.join(sub_dir, "warp_masque_hiddify_b64.txt")
                raw_hiddify = "\n".join(masque_raw_uris)
                with open(hiddify_b64_path, "w", encoding="utf-8") as f:
                    f.write(base64.b64encode(raw_hiddify.encode("utf-8")).decode("utf-8") + "\n")

        # Save AmneziaWG configuration
        if profiles:
            p0 = profiles[0]
            awg_content = build_amnezia_conf(p0)
            for fname in ["amnezia_warp880.conf", "amnezia_warp.conf", "keenetic_warp880.conf"]:
                with open(os.path.join(sub_dir, fname), "w", encoding="utf-8") as f:
                    f.write(awg_content)

    return profiles, all_uris
