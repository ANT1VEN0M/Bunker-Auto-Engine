import os
import json
import base64
import urllib.request
import urllib.parse
import subprocess
from concurrent.futures import ThreadPoolExecutor

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
                'reserved': reserved_str,
                'client_id': client_id,
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
        f"mtu={profile.get('mtu', 1280)}&dns={profile.get('remote_dns', '1.1.1.1')}#{encoded_remarks}"
    )

import time

def generate_warp_pool(count: int = 8, sub_dir: str = None) -> tuple[list[dict], list[str]]:
    """
    Generates a pool of active Cloudflare WARP WireGuard accounts with rate-limit pacing,
    saves sub/warp_pool.json and returns (profiles, uris).
    """
    endpoints = (CLOUDFLARE_ENDPOINTS * ((count // len(CLOUDFLARE_ENDPOINTS)) + 2))[:count]
    profiles = []
    
    for ip in endpoints:
        p = generate_single_warp_profile(ip, 880)
        if p:
            profiles.append(p)
            print(f"[+] WARP node generated: {ip}:880 reserved={p['reserved']}")
        if len(profiles) >= count:
            break
        time.sleep(1.2)  # Cloudflare rate limit pacing

    uris = []
    for idx, p in enumerate(profiles, 1):
        remark = f"🚀 ⚡ [WARP+] Бункер Ультра #{idx:02d} | 880 | ⚡50ms"
        uris.append(build_wireguard_uri(p, remark))

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

    return profiles, uris
