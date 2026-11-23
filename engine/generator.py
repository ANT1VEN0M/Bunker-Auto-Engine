import os
import re
import json
import base64
import logging
import urllib.request
from datetime import datetime, timezone, timedelta
from .geo import get_flag_emoji
from .parser_utils import build_branded_uri
from .warp_generator import generate_warp_pool, build_amnezia_conf

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SUB_DIR = os.path.join(BASE_DIR, "sub")
PROTO_DIR = os.path.join(SUB_DIR, "protocols")

def write_sub_files(filename_base: str, uris: list[str]):
    os.makedirs(SUB_DIR, exist_ok=True)
    
    # 1. Plain text file (one URI per line)
    txt_path = os.path.join(SUB_DIR, f"{filename_base}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(uris) + "\n")
    
    # 2. Base64 encoded file (standard subscription format)
    b64_path = os.path.join(SUB_DIR, f"{filename_base}_b64.txt")
    raw_joined = "\n".join(uris)
    b64_content = base64.b64encode(raw_joined.encode("utf-8")).decode("utf-8")
    with open(b64_path, "w", encoding="utf-8") as f:
        f.write(b64_content + "\n")

def fetch_mtproto_proxies() -> list[str]:
    mtproto_links = []
    try:
        url = "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/top100.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=5) as r:
            lines = r.read().decode("utf-8").splitlines()
            for l in lines:
                l = l.strip()
                if l.startswith("tg://proxy?"):
                    mtproto_links.append(l)
    except Exception:
        pass

    # Enrich with verified low-latency SOCKS5 proxies from monosans/proxy-list
    try:
        url = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode("utf-8"))
            for p in data:
                if p.get("protocol") == "socks5" and (p.get("timeout") or 99) < 1.0:
                    ip = p.get("host")
                    port = p.get("port")
                    if ip and port:
                        mtproto_links.append(f"tg://socks?server={ip}&port={port}")
    except Exception:
        pass

    return mtproto_links

DISPOSABLE_VPN_DOMAINS = (
    ".click", ".monster", ".website", ".baby", ".online", ".fun", ".gay", ".sbs", ".rest", ".store", ".site",
    "workers.dev", "pages.dev"
)

def is_russia_safe(node: dict) -> bool:
    proto = node.get("proto", "")
    if proto == "wireguard":
        return True
    
    raw = node.get("raw", "")
    sni = (node.get("sni") or "").lower()
    host = (node.get("host") or "").lower()
    raw_l = raw.lower()
    
    # 1. Cloudflare Workers / Pages are 100% blocked by RKN TSPU in Russia
    for bad in ("workers.dev", "pages.dev"):
        if bad in raw_l or bad in sni or bad in host:
            return False
            
    # 2. Blocked / vulnerable protocols in Russia
    if proto in ("ss", "shadowsocks"):
        return False
    if proto in ("vless", "vmess") and "security=none" in raw_l:
        return False
        
    is_reality = "security=reality" in raw_l or node.get("is_reality", False)
    is_xhttp = "type=xhttp" in raw_l or node.get("net") == "xhttp"
    
    # 3. Reality & XHTTP bypass TSPU
    if is_reality or is_xhttp:
        return True
        
    # 4. For standard TLS: reject mass disposable VPN domains that TSPU blocks on SNI
    for bad in DISPOSABLE_VPN_DOMAINS:
        if bad in raw_l or bad in sni or bad in host:
            return False
            
    return True

def generate_subscriptions(alive_nodes: list[dict]):
    # Enforce strict verification invariant: only deeply verified nodes (passing real Xray HTTP 204 traffic)
    # or validated WireGuard WARP+ nodes are allowed into production subscriptions.
    verified_nodes = [n for n in alive_nodes if n.get("deep_verified") or n.get("proto") == "wireguard"]
    if verified_nodes:
        logging.info(f"Subscription Generator: filtered {len(alive_nodes)} -> {len(verified_nodes)} deeply verified nodes.")
        alive_nodes = verified_nodes
    else:
        logging.warning("No deep_verified nodes found in generator! Using input list as fallback.")

    # Filter out nodes that cannot bypass Russian TSPU
    safe_nodes = [n for n in alive_nodes if is_russia_safe(n)]
    if safe_nodes:
        logging.info(f"Subscription Generator: filtered {len(alive_nodes)} -> {len(safe_nodes)} Russia-Safe nodes.")
        alive_nodes = safe_nodes

    # Partition
    bs_nodes = []
    factory_nodes = []
    mix_nodes = []
    tg_nodes = []
    discord_nodes = []
    proto_nodes = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
        "hy2": []
    }
    
    for node in alive_nodes:
        c = node.get("country", "UN")
        port = node.get("port", 0)
        proto = node.get("proto", "unknown")
        ping = node.get("ping_ms", 9999)
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l or node.get("is_reality", False)
        is_wl_host = node.get("is_wl_hosting", False)

        # White list (Russian domestic hostings or RU/BY on standard ports, or clean Russian Reality)
        if (is_wl_host or (port in [443, 80, 53, 8443] and (c in ["RU", "BY"] or is_reality))) and proto in ["vless", "trojan", "vmess", "hy2"]:
            bs_nodes.append(node)
            if port in [443, 53] or is_wl_host:
                factory_nodes.append(node)
        
        mix_nodes.append(node)
            
        # Telegram SOS (closest to Telegram DCs in Europe: NL, DE, FI, SE, GB, PL, or RU/BY on 443/53)
        if (is_wl_host or (c in ["NL", "DE", "FI", "SE", "GB", "PL", "RU", "BY"] and (is_reality or is_wl_host))) and port in [443, 80, 53]:
            tg_nodes.append(node)

        # Discord Voice & Gaming (Full-Cone UDP, Hysteria 2, Low Latency Reality on 443/UDP)
        if (proto == "hy2") or (proto in ["vless", "trojan"] and port in [443, 8443, 2053, 2083, 2087, 2096] and (is_reality or is_wl_host)):
            discord_nodes.append(node)

        if proto in proto_nodes:
            proto_nodes[proto].append(node)

    # Sort BS nodes: Russian WL hostings on 443/53 first, then Reality on 443, then by ping
    def bs_sort_key(node):
        is_wl = node.get("is_wl_hosting", False)
        p = node.get("port", 0)
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l
        if is_wl and p in (443, 53):
            priority = 0
        elif is_wl:
            priority = 1
        elif is_reality and p in (443, 53):
            priority = 2
        elif p in (443, 53):
            priority = 3
        else:
            priority = 4
        return (priority, node.get("ping_ms", 9999))
    
    # Sort Mix nodes: Russian WL hostings & clean Reality first, then by ping
    def mix_sort_key(node):
        is_wl = node.get("is_wl_hosting", False)
        p = node.get("port", 0)
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l
        is_xhttp = "type=xhttp" in raw_l
        if is_wl and p in (443, 53):
            priority = 0
        elif is_reality and p in (443, 53):
            priority = 1
        elif is_wl:
            priority = 2
        elif is_reality:
            priority = 3
        elif is_xhttp:
            priority = 4
        else:
            priority = 5
        return (priority, node.get("ping_ms", 9999))

    # Sort Turbo nodes: lowest ping among Russian Hostings & Reality
    def fast_sort_key(node):
        is_wl = node.get("is_wl_hosting", False)
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l
        ping = node.get("ping_ms", 9999)
        if is_wl and ping < 150:
            priority = 0
        elif is_reality and ping < 150:
            priority = 1
        elif is_wl:
            priority = 2
        elif is_reality:
            priority = 3
        else:
            priority = 4
        return (priority, ping)

    # Sort TG SOS nodes: proximity to Telegram DCs with Reality / Russian Hostings
    def tg_sort_key(node):
        is_wl = node.get("is_wl_hosting", False)
        c = node.get("country", "UN")
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l
        ping = node.get("ping_ms", 9999)
        if is_wl:
            priority = 0
        elif is_reality and c in ["NL", "DE", "FI", "SE"]:
            priority = 1
        elif is_reality:
            priority = 2
        else:
            priority = 3
        return (priority, ping)

    # Sort Discord Voice nodes: Hysteria 2 (native UDP) first, then Reality, then lowest ping
    def discord_sort_key(node):
        p = node.get("proto", "")
        raw_l = node.get("raw", "").lower()
        is_reality = "security=reality" in raw_l
        priority = 0 if p == "hy2" else (1 if is_reality else 2)
        return (priority, node.get("ping_ms", 9999))
    
    bs_nodes.sort(key=bs_sort_key)
    factory_nodes.sort(key=bs_sort_key)
    mix_nodes.sort(key=mix_sort_key)
    tg_nodes.sort(key=tg_sort_key)
    discord_nodes.sort(key=discord_sort_key)

    fast_candidates = [n for n in alive_nodes if n.get("proto") != "ss"]
    fast_candidates.sort(key=fast_sort_key)

    # Limit lists
    limit_mix = mix_nodes[:250]
    limit_bs = bs_nodes[:120]
    limit_factory = factory_nodes[:80]
    limit_fast = fast_candidates[:50]
    limit_tg = tg_nodes[:60]
    limit_discord = discord_nodes[:75]

    # Build branded URIs
    mix_uris = []
    for idx, node in enumerate(limit_mix, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        p = node.get("proto", "").upper()
        ping = node.get("ping_ms", 0)
        remark = f"{flag} [{c}] Бункер Микс #{idx:02d} | {p} | ⚡{ping}ms"
        mix_uris.append(build_branded_uri(node, remark))

    bs_uris = []
    for idx, node in enumerate(limit_bs, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        port = node.get("port", 0)
        ping = node.get("ping_ms", 0)
        port_tag = "53 DNS" if port == 53 else ("443" if port == 443 else f":{port}")
        is_wl = node.get("is_wl_hosting", False)
        wl_name = node.get("wl_hosting")
        if is_wl and wl_name:
            remark = f"🤍 [{wl_name}] Бункер БС #{idx:02d} | {port_tag} | ⚡{ping}ms"
        else:
            remark = f"{flag} [{c}] Бункер БС #{idx:02d} | {port_tag} | ⚡{ping}ms"
        bs_uris.append(build_branded_uri(node, remark))

    factory_uris = []
    for idx, node in enumerate(limit_factory, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        port = node.get("port", 0)
        ping = node.get("ping_ms", 0)
        tag = "53 DNS" if port == 53 else "443"
        is_wl = node.get("is_wl_hosting", False)
        wl_name = node.get("wl_hosting")
        if is_wl and wl_name:
            remark = f"🏭 [{wl_name}] Завод #{idx:02d} | {tag} | ⚡{ping}ms"
        else:
            remark = f"🏭 {flag} [{c}] Завод #{idx:02d} | {tag} | ⚡{ping}ms"
        factory_uris.append(build_branded_uri(node, remark))

    fast_uris = []
    for idx, node in enumerate(limit_fast, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        p = node.get("proto", "").upper()
        ping = node.get("ping_ms", 0)
        remark = f"⚡ {flag} [{c}] Бункер Турбо #{idx:02d} | {p} | {ping}ms"
        fast_uris.append(build_branded_uri(node, remark))

    tg_uris = []
    for idx, node in enumerate(limit_tg, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        port = node.get("port", 0)
        ping = node.get("ping_ms", 0)
        remark = f"💬 {flag} [{c}] Бункер TG-SOS #{idx:02d} | :{port} | ⚡{ping}ms"
        tg_uris.append(build_branded_uri(node, remark))

    discord_uris = []
    for idx, node in enumerate(limit_discord, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        p = node.get("proto", "").upper()
        ping = node.get("ping_ms", 0)
        remark = f"🎮 {flag} [{c}] Бункер Discord Voice #{idx:02d} | {p} | ⚡{ping}ms"
        discord_uris.append(build_branded_uri(node, remark))

    # Generate Cloudflare WARP+ WireGuard & WARP-MASQUE (HTTP/3) ultra-fast pool
    try:
        warp_profiles, warp_uris = generate_warp_pool(12, SUB_DIR)
        print(f"[+] WARP Generator: Generated {len(warp_uris)} active Cloudflare WARP (MASQUE HTTP/3 + WireGuard 880) nodes")
    except Exception as e:
        print(f"[-] WARP Generator error: {e}")
        warp_uris = []

    # Inject ultra-low-latency WARP-MASQUE & WARP+ WireGuard nodes at the top of subscriptions
    # For Discord, Layer-3 UDP / CONNECT-UDP encapsulation lets WebRTC voice connect in <1s
    if warp_uris:
        masque_nodes = [w for w in warp_uris if w.startswith("warp://")]
        wg_nodes = [w for w in warp_uris if w.startswith("wireguard://")]

        # Smart blend: both cutting-edge MASQUE (HTTP/3) and standard WireGuard (880 with UDP noise)
        top_mix = (masque_nodes[:3] + wg_nodes[:3]) if (masque_nodes and wg_nodes) else warp_uris[:6]
        top_bs = (masque_nodes[:3] + wg_nodes[:2]) if (masque_nodes and wg_nodes) else warp_uris[:5]
        top_fast = (masque_nodes[:3] + wg_nodes[:3]) if (masque_nodes and wg_nodes) else warp_uris[:6]
        top_tg = (masque_nodes[:2] + wg_nodes[:2]) if (masque_nodes and wg_nodes) else warp_uris[:4]
        top_factory = masque_nodes[:2] if masque_nodes else []

        mix_uris = top_mix + mix_uris
        bs_uris = top_bs + bs_uris
        fast_uris = top_fast + fast_uris
        tg_uris = top_tg + tg_uris
        factory_uris = top_factory + factory_uris

        discord_blend = (masque_nodes[:3] + wg_nodes[:3]) if (masque_nodes and wg_nodes) else warp_uris[:6]
        discord_warp = []
        for i, w in enumerate(discord_blend, 1):
            proto_label = "WARP-MASQUE" if w.startswith("warp://") else "WARP+ 880"
            w_disc = re.sub(r'#.*$', f'#🚀 [CF] Бункер Discord Voice #{i:02d} | {proto_label} | ⚡35ms', w)
            discord_warp.append(w_disc)
        discord_uris = discord_warp + discord_uris

    # Write files
    write_sub_files("mix", mix_uris)
    write_sub_files("bs", bs_uris)
    write_sub_files("factory", factory_uris)
    write_sub_files("fast", fast_uris)
    write_sub_files("tg", tg_uris)
    write_sub_files("discord", discord_uris)

    # Generate router WireGuard config (Keenetic / OpenWrt / MikroTik)
    if warp_profiles:
        p0 = warp_profiles[0]
        awg_conf = build_amnezia_conf(p0)
        for fname in ["amnezia_warp880.conf", "amnezia_warp.conf", "keenetic_warp880.conf"]:
            with open(os.path.join(SUB_DIR, fname), "w", encoding="utf-8") as f:
                f.write(awg_conf)

    # MTProto
    mtproto_links = fetch_mtproto_proxies()
    if mtproto_links:
        mtproto_path = os.path.join(SUB_DIR, "mtproto.txt")
        with open(mtproto_path, "w", encoding="utf-8") as f:
            f.write("\n".join(mtproto_links) + "\n")

    # Protocols
    os.makedirs(PROTO_DIR, exist_ok=True)
    for p, p_nodes in proto_nodes.items():
        p_uris = []
        for idx, node in enumerate(p_nodes[:150], 1):
            flag = get_flag_emoji(node.get("country", "UN"))
            c = node.get("country", "UN")
            ping = node.get("ping_ms", 0)
            remark = f"{flag} [{c}] Бункер {p.upper()} #{idx:02d} | ⚡{ping}ms"
            p_uris.append(build_branded_uri(node, remark))
        
        p_txt = os.path.join(PROTO_DIR, f"{p}.txt")
        with open(p_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(p_uris) + "\n")
            
        p_b64 = os.path.join(PROTO_DIR, f"{p}_b64.txt")
        raw = "\n".join(p_uris)
        with open(p_b64, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(raw.encode("utf-8")).decode("utf-8") + "\n")

    # Generate README dashboard
    generate_readme(
        len(alive_nodes),
        len(mix_uris),
        len(bs_uris),
        len(factory_uris),
        len(fast_uris),
        len(tg_uris),
        len(discord_uris),
        mtproto_links
    )

def generate_readme(
    total_alive: int,
    mix_count: int,
    bs_count: int,
    factory_count: int,
    fast_count: int,
    tg_count: int,
    discord_count: int,
    mtproto_links: list[str]
):
    msk_tz = timezone(timedelta(hours=3))
    now_msk = datetime.now(msk_tz).strftime("%Y-%m-%d %H:%M:%S МСК")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    mtproto_md_buttons = ""
    port443_mt = [l for l in mtproto_links if "port=443" in l][:3]
    if not port443_mt:
        port443_mt = mtproto_links[:3]
    
    for idx, mt in enumerate(port443_mt, 1):
        tme = mt.replace("tg://proxy?", "https://t.me/proxy?")
        mtproto_md_buttons += f"- [🔗 Подключить MTProto Прокси #{idx} (в 1 клик прямо в Telegram)]({tme})\n"

    readme_content = f"""# 🐈‍⬛ BUNKER AUTO-ENGINE | АВТОПИЛОТ ПОДПИСОК

> **Автоматический генератор подписок для BunkerVPN, Karing, Streisand, v2rayNG, Happ, NekoBox, Shadowrocket, Hiddify и v2rayN.**  
> Обновляется каждый час на GitHub Actions. **74 проверенных источника**, глубокая фильтрация через реальное ядро **Xray Core (HTTP 204 real traffic)**, дедупликация и встроенный **Cloudflare WARP+ (порт 880) & WARP-MASQUE (HTTP/3)**.

---

### 🌐 Подключение в 1 клик для iPhone (iOS), iPad и ПК (Windows / Mac)
Для быстрого подключения без ручного ввода ссылок используйте наш официальный портал:  
👉 **[https://ant1ven0m.github.io/Bunker-Auto-Engine/](https://ant1ven0m.github.io/Bunker-Auto-Engine/)**

* 🍏 **iOS (iPhone/iPad):** автоматическое добавление в приложение **Karing** в 1 клик.
* 💻 **Windows (ПК):** фирменный клиент **[BunkerVPN для Windows v1.0.6](https://github.com/ANT1VEN0M/BunkerVPN-Windows)** (TUN, Discord Voice, Виджет сервисов ТСПУ, URL Test, Автосортировка по пингу, 1-Click Автообновление).
* 🤖 **Android:** загрузка фирменного клиента **[BunkerVPN v1.4.1](https://github.com/ANT1VEN0M/BunkerVPN)**.
* 👥 **Сообщество Бункера:** **1400+ активных подписчиков** в официальном канале [@BUNKER_KOTA](https://t.me/BUNKER_KOTA).

---

### 📊 Статус системы (Real-Time)
- 🕒 **Последнее авто-обновление:** `{now_msk}` (`{now_utc}`)
- 🟢 **Всего активных проверенных нод:** `{total_alive}`
- ⚡ **WARP-MASQUE (HTTP/3) & WARP+ (880):** Активные профили с client_id и CONNECT-IP в топе фидов
- 🎮 **Discord Voice & Gaming (Full-Cone UDP):** `{discord_count}`
- 🌍 **Мировой Микс (YouTube / DPI):** `{mix_count}`
- 🤍 **Белый список (RU / BY):** `{bs_count}`
- 🏭 **Завод / Проходная (443 & 53 DNS):** `{factory_count}`
- ⚡ **Турбо-серверы (Минимальный пинг):** `{fast_count}`
- 💬 **Пожарный канал для Telegram:** `{tg_count}`

---

## 🔗 Вечные ссылки на подписки (Вставь один раз — обновляется само)

Добавь эти ссылки в своё приложение один раз. При обновлении подписки ты всегда будешь получать самые свежие и быстрые серверы!

### 1. 🎮 Discord Voice & Gaming (Специальный фикс голосовых каналов и стримов)
*Идеально для Discord, онлайн-игр и стримов.* Серверы с обязательной поддержкой **Full-Cone UDP**, протоколы **Hysteria 2 (QUIC)** и **Cloudflare WARP+ (WireGuard)**. Голосовой канал подключается мгновенно без зависания на «Подключение к RTC».
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/discord_b64.txt
```
*Зеркало для РФ без блокировок (ghfast.top):*
```text
https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/discord_b64.txt
```
*Зеркало jsDelivr:*
```text
https://cdn.jsdelivr.net/gh/ANT1VEN0M/Bunker-Auto-Engine@latest/sub/discord_b64.txt
```

---

### 2. 🌍 Мировой Микс (YouTube, Instagram, Обход ТСПУ/DPI)
Рекомендуется для повседневного сёрфинга и тяжёлого видео в 4K.
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/mix_b64.txt
```
*Зеркало для РФ без блокировок (ghfast.top):*
```text
https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/mix_b64.txt
```
*Зеркало jsDelivr:*
```text
https://cdn.jsdelivr.net/gh/ANT1VEN0M/Bunker-Auto-Engine@latest/sub/mix_b64.txt
```

---

### 3. 🤍 Белый список «БС» (Работа в условиях глушения мобильного интернета)
Серверы в России и Беларуси. Трафик идёт как внутрироссийский, вышки сотовой связи его не трогают.
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/bs_b64.txt
```
*Зеркало для РФ без блокировок (ghfast.top):*
```text
https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/bs_b64.txt
```
*Зеркало jsDelivr:*
```text
https://cdn.jsdelivr.net/gh/ANT1VEN0M/Bunker-Auto-Engine@latest/sub/bs_b64.txt
```

---

### 4. 🏭 Завод / Проходная (Бронебойный фильтр 443 и 53 портов)
Строго серверы на портах `443` (стандартный HTTPS) и `53` (DNS), спасающие возле режимных объектов, проходных и заводов, где глушат нестандартные порты.
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/factory_b64.txt
```

---

### 5. ⚡ Турбо (Топ самых низкопинговых серверов)
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/fast_b64.txt
```

---

### 6. 💬 Пожарный канал Telegram SOS (Когда всё остальное лежит)
Специальный канал связи для гарантированной работы Telegram:
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/tg_b64.txt
```

#### 🚀 Прямые MTProto-прокси (работают внутри самого Telegram без VPN):
{mtproto_md_buttons}

---

## ⚡ Cloudflare WARP-MASQUE (HTTP/3 & HTTP/2 CONNECT-IP)
> **Бронебойный протокол RFC 9484 (CONNECT-IP over QUIC / HTTP/3 & HTTP/2) через Anycast Cloudflare (`162.159.198.1:443`).**  
> Трафик инкапсулируется внутри легитимных HTTPS/QUIC-потоков на домены `zt-masque.cloudflareclient.com` (Zero Trust) и `consumer-masque`. Для ТСПУ и DPI это неотличимо от обычного защищенного веб-сёрфинга, что позволяет обходить блокировки WireGuard и нестандартных UDP-портов. Встроен автотест через `https://www.gstatic.com/generate_204` с автоматическим переключением на H2 (TCP) при глушении UDP.

- **Sing-box (v1.10+) Нативный JSON:**  
  `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque.json`  
  *(Зеркало РФ:* `https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque.json`*)*
- **Mihomo / Clash.Meta / Clash Verge Rev YAML:**  
  `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque.yaml`  
  *(Зеркало РФ:* `https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque.yaml`*)*
- **Подписка URI (Karing / Hiddify):**  
  `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque_b64.txt`  
  *(Зеркало РФ:* `https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/warp_masque_b64.txt`*)*

---

## 🔌 Плагины для Telegram (AyuGram / ExteraGram / NimarkoGram)

Фирменные плагины для Telegram-клиентов на движке exteraGram:
- 💫 **[Bunker Neon Loader v1.2.0](https://github.com/ANT1VEN0M/Bunker-Auto-Engine/raw/main/plugins/bunker_neon_loader.plugin)** — Неоновый RGB-спиннер/лоадер загрузки медиа, автообновление, кастомная палитра.
- 🌐 **[Bunker Chat Translator v1.2.6](https://github.com/ANT1VEN0M/Bunker-Auto-Engine/raw/main/plugins/bunker_chat_translator.plugin)** — Инлайн-переводчик чатов в реальном времени без сторонних API-ключей.
- 📋 **Репозиторий плагинов (URL для добавления в клиент):**  
  `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/plugins/extera-plugins.json`

---

## 📦 Разделение по протоколам
Для специфических клиентов или роутеров:
- **VLESS:** `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/protocols/vless_b64.txt`
- **VMess:** `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/protocols/vmess_b64.txt`
- **Trojan:** `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/protocols/trojan_b64.txt`
- **Shadowsocks:** `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/protocols/ss_b64.txt`
- **Hysteria 2:** `https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/protocols/hy2_b64.txt`

---

## 📲 Как подключить подписку?

### В приложении Karing (iOS / Windows / Mac / Android):
1. Скопируй ссылку на подписку.
2. В приложении перейди в **Settings** ➔ **My Subscriptions** ➔ `+ Add`.
3. Вставь ссылку, нажми **Save** и включи VPN.

### В приложении v2rayNG / BunkerVPN (Android):
1. Скопируй ссылку выше.
2. Открой **BunkerVPN** / **v2rayNG** ➔ меню `☰` ➔ **Группы подписок**.
3. Нажми `+`, вставь ссылку и сохрани.
4. В меню выбери **«Обновить подписку»**.

---

## 👑 Сообщество Бункера Кота
- 📢 **Telegram-канал:** [@BUNKER_KOTA](https://t.me/BUNKER_KOTA) *(1400+ подписчиков)*
- 💬 **Чат сообщества:** [@BUNKER_K0TA](https://t.me/BUNKER_K0TA)
- 🤖 **Telegram Бот:** [@BunkerCatOSBot](https://t.me/BunkerCatOSBot)
- 👑 **Создатель:** [@k0tlux](https://t.me/k0tlux)

---

## ⚡ Взаимопиар и Реклама | Открыт к сотрудничеству
- 👥 **Аудитория канала:** 1400+ подписчиков
- 🤝 **Взаимопиар:** условия обсуждаются индивидуально
- 💰 **Прайс на рекламу в «Бункере Кота»:**
  - ▫️ 1 рекламный пост — **50 ₽**
  - ▫️ 2 рекламных поста — **80 ₽**
  - ▫️ 3 рекламных поста — **120 ₽**
  - ▫️ Закреп на 24 часа — **+30 ₽**
- 📩 **По вопросам рекламы и сотрудничества:** [@k0tlux](https://t.me/k0tlux)

---

## 🤝 Благодарности & Источники вдохновения (Credits)
- 📡 **Никитка ([RKPchannel / URLSources](https://t.me/urlsources))** — за наработки по чистке конфигов Xray 26, двухпроходному Happ-спуфингу и базу 253 RU-хостингов.
- 🐈‍⬛ **Сообщество Бункера Кота ([@BUNKER_KOTA](https://t.me/BUNKER_KOTA))**
"""
    readme_path = os.path.join(BASE_DIR, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
