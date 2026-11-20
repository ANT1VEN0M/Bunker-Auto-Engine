import os
import base64
import urllib.request
from datetime import datetime, timezone, timedelta
from .geo import get_flag_emoji
from .parser_utils import build_branded_uri
from .warp_generator import generate_warp_pool

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
    return mtproto_links

def generate_subscriptions(alive_nodes: list[dict]):
    # Sort all by ping
    alive_nodes.sort(key=lambda x: x.get("ping_ms", 9999))
    
    # Partition
    bs_nodes = []
    factory_nodes = []
    mix_nodes = []
    tg_nodes = []
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
        
        # Plain Shadowsocks is blocked by Russian TSPU (entropy detection)
        # SS goes strictly into protocol-specific file (protocols/ss.txt), NEVER into general subscriptions!
        if proto == "ss":
            proto_nodes["ss"].append(node)
            continue

        # White list (Bypass restrictive Wi-Fi / enterprise firewall: standard ports 443, 80, 53, 8443)
        if port in [443, 80, 53, 8443] and proto in ["vless", "trojan", "vmess", "hy2"]:
            bs_nodes.append(node)
            if port in [443, 53]:
                factory_nodes.append(node)
        
        mix_nodes.append(node)
            
        # Telegram SOS (closest to Telegram DCs in Europe: NL, DE, FI, SE, GB, PL, or RU/BY on 443/53)
        if port in [443, 80, 53] and c in ["NL", "DE", "FI", "SE", "GB", "PL", "RU", "BY"]:
            tg_nodes.append(node)

        if proto in proto_nodes:
            proto_nodes[proto].append(node)

    # Sort BS nodes: 443 & 53 first, then by ping
    def bs_sort_key(node):
        p = node.get("port", 0)
        priority = 0 if p == 443 else (1 if p == 53 else (2 if p == 80 else 3))
        return (priority, node.get("ping_ms", 9999))
    
    bs_nodes.sort(key=bs_sort_key)
    factory_nodes.sort(key=bs_sort_key)
    mix_nodes.sort(key=lambda x: x.get("ping_ms", 9999))
    tg_nodes.sort(key=lambda x: x.get("ping_ms", 9999))

    fast_candidates = [n for n in alive_nodes if n.get("proto") != "ss"]
    fast_candidates.sort(key=lambda x: x.get("ping_ms", 9999))

    # Limit lists
    limit_mix = mix_nodes[:250]
    limit_bs = bs_nodes[:120]
    limit_factory = factory_nodes[:80]
    limit_fast = fast_candidates[:50]
    limit_tg = tg_nodes[:60]

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
        remark = f"{flag} [{c}] Бункер БС #{idx:02d} | {port_tag} | ⚡{ping}ms"
        bs_uris.append(build_branded_uri(node, remark))

    factory_uris = []
    for idx, node in enumerate(limit_factory, 1):
        flag = get_flag_emoji(node.get("country", "UN"))
        c = node.get("country", "UN")
        port = node.get("port", 0)
        ping = node.get("ping_ms", 0)
        tag = "53 DNS" if port == 53 else "443"
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

    # Generate Cloudflare WARP+ WireGuard ultra-fast pool
    try:
        warp_profiles, warp_uris = generate_warp_pool(12, SUB_DIR)
        print(f"[+] WARP Generator: Generated {len(warp_uris)} active Cloudflare WARP+ WireGuard nodes (port 880)")
    except Exception as e:
        print(f"[-] WARP Generator error: {e}")
        warp_uris = []

    # Inject ultra-low-latency WARP+ WireGuard nodes at the top of subscriptions
    if warp_uris:
        mix_uris = warp_uris[:5] + mix_uris
        bs_uris = warp_uris[:4] + bs_uris
        fast_uris = warp_uris[:5] + fast_uris
        tg_uris = warp_uris[:3] + tg_uris

    # Write files
    write_sub_files("mix", mix_uris)
    write_sub_files("bs", bs_uris)
    write_sub_files("factory", factory_uris)
    write_sub_files("fast", fast_uris)
    write_sub_files("tg", tg_uris)

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
    generate_readme(len(alive_nodes), len(mix_uris), len(bs_uris), len(factory_uris), len(fast_uris), len(tg_uris), mtproto_links)

def generate_readme(total_alive: int, mix_count: int, bs_count: int, factory_count: int, fast_count: int, tg_count: int, mtproto_links: list[str]):
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

> **Автоматический генератор подписок для BunkerVPN, v2rayNG, Happ, NekoBox, Shadowrocket и v2rayN.**  
> Обновляется каждые 6 часов на GitHub Actions. Только живые, проверенные ноды с дедупликацией, очисткой от рекламы и разделением по режимам.

---

### 📊 Статус системы (Real-Time)
- 🕒 **Последнее авто-обновление:** `{now_msk}` (`{now_utc}`)
- 🟢 **Всего активных проверенных нод:** `{total_alive}`
- 🌍 **Мировой Микс (YouTube / DPI):** `{mix_count}`
- 🤍 **Белый список (RU / BY):** `{bs_count}`
- 🏭 **Завод / Проходная (443 & 53 DNS):** `{factory_count}`
- ⚡ **Турбо-серверы (Минимальный пинг):** `{fast_count}`
- 💬 **Пожарный канал для Telegram:** `{tg_count}`

---

## 🔗 Вечные ссылки на подписки (Вставь один раз — обновляется само)

Добавь эти ссылки в своё приложение один раз. При обновлении подписки ты всегда будешь получать самые свежие и быстрые серверы!

### 1. 🌍 Мировой Микс (YouTube, Discord, Instagram, Обход ТСПУ/DPI)
Рекомендуется для повседневного сёрфинга и тяжёлого видео. Только зарубежные серверы (Нидерланды, Германия, Финляндия, США, Швеция).
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/mix_b64.txt
```
*Зеркало jsDelivr (если GitHub заблокирован провайдером):*
```text
https://cdn.jsdelivr.net/gh/ANT1VEN0M/Bunker-Auto-Engine@main/sub/mix_b64.txt
```

---

### 2. 🤍 Белый список «БС» (Работа в условиях локального глушения)
Серверы в России и Беларуси. Трафик идёт как внутрироссийский, вышки сотовой связи его не трогают.
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/bs_b64.txt
```
*Зеркало jsDelivr:*
```text
https://cdn.jsdelivr.net/gh/ANT1VEN0M/Bunker-Auto-Engine@main/sub/bs_b64.txt
```

---

### 3. 🏭 Завод / Проходная (Бронебойный фильтр 443 и 53 портов)
Строго серверы на портах `443` (стандартный HTTPS) и `53` (DNS), спасающие возле режимных объектов, проходных и заводов, где глушат нестандартные порты.
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/factory_b64.txt
```

---

### 4. ⚡ Турбо (Топ самых низкопинговых серверов)
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/fast_b64.txt
```

---

### 5. 💬 Пожарный канал Telegram SOS (Когда всё остальное лежит)
Специальный канал связи для гарантированной работы Telegram (обновление ссылок, чтение постов и связь, когда внешние протоколы душатся вышкой):
```text
https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/tg_b64.txt
```

#### 🚀 Прямые MTProto-прокси (работают внутри самого Telegram без VPN):
{mtproto_md_buttons}

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

### В приложении v2rayNG (Android):
1. Скопируй ссылку выше.
2. Открой **v2rayNG** -> нажми `☰` (боковое меню) -> **Группы подписок**.
3. Нажми `+`, в поле «URL подписки» вставь скопированную ссылку.
4. Нажми галочку сохранения.
5. Вернись на главный экран -> нажми три точки справа вверху -> **«Обновить подписку»**.

### В приложении BunkerVPN:
1. Перейди в раздел подписок или настроек.
2. Вставь ссылку в поле «URL подписки» и нажми **Обновить**.

---

## 👑 Сообщество Бункера Кота
- 📢 **Telegram-канал:** [@BUNKER_KOTA](https://t.me/BUNKER_KOTA)
- 💬 **Чат сообщества:** [@BUNKER_K0TA](https://t.me/BUNKER_K0TA)
- 🤖 **Telegram Бот:** [@BunkerCatOSBot](https://t.me/BunkerCatOSBot)
- 👑 **Создатель:** [@k0tlux](https://t.me/k0tlux)
"""
    readme_path = os.path.join(BASE_DIR, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
