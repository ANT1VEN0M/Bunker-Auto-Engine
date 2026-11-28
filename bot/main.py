# -*- coding: utf-8 -*-
"""
🐈‍⬛ BUNKER CAT OS BOT — OFFICIAL INTERACTIVE ASSISTANT
Сообщество «Бункер Кота» (1400+ подписчиков)
Создатель: @k0tlux / @Titandarkness (KOT ANTIDOT)
"""

import os
import sys
import time
import shutil
import sqlite3
import logging
import telebot
from telebot import types

TOKEN = "9044730839:AAEP6kanpZi_tuei6HDE-P1i1aR8WXvIBzI"
ADMIN_IDS = [6385528140, 5608909722]
ADMIN_USERNAMES = ["titandarkness", "k0tlux"]

CHANNEL_USERNAME = "BUNKER_KOTA"
CHAT_USERNAME = "BUNKER_K0TA"
ANTIDPI_ZIP_PATH = "/root/.gemini/antigravity-cli/scratch/Bunker_AntiDPI_v1.0.zip"
NETMERGE_ZIP_PATH = "/root/.gemini/antigravity-cli/scratch/Bunker_NetMerge_v1.0.zip"
APK_PATH = "/root/.gemini/antigravity-cli/scratch/bunker_vpn_v149.apk"
MTPROTO_PATH = "/root/.gemini/antigravity-cli/scratch/Bunker-Auto-Engine/sub/mtproto.txt"
SUBS_DIR = "/root/.gemini/antigravity-cli/scratch/Bunker-Auto-Engine/sub"
DB_PATH = "/root/.gemini/antigravity-cli/scratch/bunker_bot/bunker_bot_users.db"
OZON_SBP_LINK = "https://finance.ozon.ru/apps/sbp/ozonbankpay/01a1daa7-59df-7009-9fee-796763044ce6"

APK_ARM64_URL = "https://github.com/ANT1VEN0M/BunkerVPN/releases/download/v1.4.9/BunkerVPN-arm64-v8a.apk"
APK_UNIVERSAL_URL = "https://github.com/ANT1VEN0M/BunkerVPN/releases/download/v1.4.9/BunkerVPN-universal.apk"
RELEASE_PAGE_URL = "https://github.com/ANT1VEN0M/BunkerVPN/releases/tag/v1.4.9"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# Кеш file_id после первой загрузки файлов в Telegram
CACHED_FILE_IDS = {
    "apk": None,
    "antidpi": None,
    "netmerge": None
}

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error initializing database: {e}")

def save_user(user):
    if not user:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (user_id, username, first_name, last_name, last_active)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name,
                last_name=excluded.last_name,
                last_active=CURRENT_TIMESTAMP
        """, (user.id, user.username or "", user.first_name or "", user.last_name or ""))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Error saving user: {e}")

def get_user_count():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        cnt = cur.fetchone()[0]
        conn.close()
        return cnt
    except Exception:
        return 0

def get_all_user_ids():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM users")
        ids = [row[0] for row in cur.fetchall()]
        conn.close()
        return ids
    except Exception:
        return []

def is_admin(user) -> bool:
    if not user:
        return False
    uid = getattr(user, "id", None)
    uname = (getattr(user, "username", "") or "").lower().lstrip("@")
    return (uid in ADMIN_IDS) or (uname in ADMIN_USERNAMES)

def get_mtproto_proxies():
    proxies = []
    if os.path.exists(MTPROTO_PATH):
        try:
            with open(MTPROTO_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("tg://proxy?"):
                        url = line.replace("tg://proxy?", "https://t.me/proxy?")
                        proxies.append(url)
                    elif line.startswith("https://t.me/proxy?"):
                        proxies.append(line)
                    if len(proxies) >= 6:
                        break
        except Exception as e:
            logging.error(f"Error reading mtproto.txt: {e}")
    return proxies

def get_sub_stats():
    stats = {}
    files = {"mix.txt": "Микс", "bs.txt": "Белый список", "gold.txt": "Gold VIP", "fast.txt": "Турбо"}
    for fname, label in files.items():
        p = os.path.join(SUBS_DIR, fname)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                lines = [l for l in f if l.strip()]
                stats[label] = len(lines)
        else:
            stats[label] = 0
    return stats

def get_main_keyboard(is_user_admin=False):
    kb = types.InlineKeyboardMarkup(row_width=1)
    btn_apk = types.InlineKeyboardButton("📱 Скачать Bunker VPN Android (v1.4.9)", callback_data="get_apk")
    btn_win = types.InlineKeyboardButton("💻 Скачать Bunker VPN Windows (v1.0.14)", callback_data="get_win")
    btn_netmerge = types.InlineKeyboardButton("🚀 Склейка интернетов (Bunker Net-Merge PC)", callback_data="get_netmerge")
    btn_sub = types.InlineKeyboardButton("⚡ Вечные подписки (1600+ серверов)", callback_data="get_sub")
    btn_tg_sos = types.InlineKeyboardButton("💬 Пожарные MTProto-прокси (Telegram SOS)", callback_data="get_tg_sos")
    btn_antidpi = types.InlineKeyboardButton("🛡️ Скачать Bunker Anti-DPI для Windows", callback_data="get_antidpi")
    btn_donate = types.InlineKeyboardButton("💖 Поддержать Бункер Кота (СБП)", callback_data="get_donate")
    btn_chat = types.InlineKeyboardButton("💬 Чат сообщества @BUNKER_K0TA", url=f"https://t.me/{CHAT_USERNAME}")
    btn_channel = types.InlineKeyboardButton("📢 Официальный канал @BUNKER_KOTA", url=f"https://t.me/{CHANNEL_USERNAME}")
    btn_portal = types.InlineKeyboardButton("🌐 Веб-портал Бункера", url="https://ant1ven0m.github.io/Bunker-Auto-Engine/")
    kb.add(btn_apk, btn_win, btn_netmerge, btn_sub, btn_tg_sos, btn_antidpi, btn_donate, btn_chat, btn_channel, btn_portal)
    
    if is_user_admin:
        btn_admin = types.InlineKeyboardButton("👑 Панель Администратора", callback_data="admin_panel")
        kb.add(btn_admin)
        
    return kb

def get_admin_keyboard():
    kb = types.InlineKeyboardMarkup(row_width=2)
    btn_stats = types.InlineKeyboardButton("📊 Статистика", callback_data="admin_stats")
    btn_subs = types.InlineKeyboardButton("⚡ Проверить подписки", callback_data="admin_check_subs")
    btn_cache = types.InlineKeyboardButton("🔄 Сброс кэша файлов", callback_data="admin_clear_cache")
    btn_admins = types.InlineKeyboardButton("👥 Администраторы", callback_data="admin_list_admins")
    btn_bcast = types.InlineKeyboardButton("📢 Инструкция рассылки", callback_data="admin_broadcast_help")
    btn_back = types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main")
    kb.add(btn_stats, btn_subs)
    kb.add(btn_cache, btn_admins)
    kb.add(btn_bcast)
    kb.add(btn_back)
    return kb

def get_admin_panel_text(user):
    uname = user.username or user.first_name or "Админ"
    u_count = get_user_count()
    sub_stats = get_sub_stats()
    
    # Disk stats
    total, used, free = shutil.disk_usage("/")
    disk_str = f"{used // (1024**3)}G / {total // (1024**3)}G"
    
    # Memory stats
    mem_str = "Н/Д"
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        m = {}
        for l in lines:
            parts = l.split(":")
            if len(parts) == 2:
                m[parts[0].strip()] = int(parts[1].strip().split()[0])
        total_m = m.get("MemTotal", 0) // 1024
        avail_m = m.get("MemAvailable", 0) // 1024
        used_m = total_m - avail_m
        mem_str = f"{used_m}M / {total_m}M"
    except Exception:
        pass

    text = (
        f"👑 <b>ПАНЕЛЬ АДМИНИСТРАТОРА | @BunkerCatOSBot</b>\n\n"
        f"Добро пожаловать, <b>@{uname}</b> (ID: <code>{user.id}</code>)!\n\n"
        f"👥 <b>Пользователей в базе бота:</b> <code>{u_count}</code> чел.\n"
        f"🖥️ <b>Сервер:</b> RAM: <code>{mem_str}</code> | Диск: <code>{disk_str}</code>\n\n"
        f"⚡ <b>Актуальные подписки Бункера:</b>\n"
        f"• 🌐 Микс: <b>{sub_stats.get('Микс', 0)}</b> серверов\n"
        f"• 🛡️ Белый список (БС): <b>{sub_stats.get('Белый список', 0)}</b> серверов\n"
        f"• 👑 Gold VIP: <b>{sub_stats.get('Gold VIP', 0)}</b> серверов\n"
        f"• 🚀 Турбо: <b>{sub_stats.get('Турбо', 0)}</b> серверов\n\n"
        f"📦 <b>Кэш Telegram file_id:</b>\n"
        f"• APK: <code>{'Загружен' if CACHED_FILE_IDS['apk'] else 'Сброшен'}</code>\n"
        f"• AntiDPI: <code>{'Загружен' if CACHED_FILE_IDS['antidpi'] else 'Сброшен'}</code>\n"
        f"• NetMerge: <code>{'Загружен' if CACHED_FILE_IDS['netmerge'] else 'Сброшен'}</code>\n"
    )
    return text

@bot.message_handler(commands=["start", "help"])
def send_welcome(message):
    save_user(message.from_user)
    user_name = message.from_user.first_name or "друг"
    user_is_admin = is_admin(message.from_user)
    
    admin_badge = " [👑 Администратор]" if user_is_admin else ""
    text = (
        f"🐈‍⬛ <b>Салют, {user_name}!{admin_badge}</b>\n\n"
        f"Добро пожаловать в официальный бот экосистемы <b>«Бункер Кота»</b> (1400+ участников).\n\n"
        f"Здесь собраны все актуальные решения для свободного интернета без блокировок и цензуры:\n"
        f"• 📱 <b>Bunker VPN v1.4.9 (Android):</b> официальное стелс-приложение с 1-Click подключением и обходом ТСПУ\n"
        f"• 💻 <b>Bunker VPN v1.0.14 (Windows):</b> нативный десктопный клиент со встроенным YouTube 4K\n"
        f"• 👑 <b>База проверенных серверов:</b> VLESS-Reality, Trojan TLS, Hysteria 2, WireGuard\n"
        f"• 🛡️ <b>Bunker Anti-DPI v1.0:</b> прямой обход ТСПУ без серверов для YouTube 4K и Discord на ПК\n"
        f"• 🚀 <b>Bunker Net-Merge v1.0:</b> склейка нескольких каналов интернета (Multi-WAN Bonding)\n"
        f"• 💬 <b>Telegram SOS:</b> прямое подключение через MTProto в 1 клик без VPN\n\n"
        f"<i>Выбери нужный раздел в меню ниже:</i> 🐾"
    )
    bot.send_message(message.chat.id, text, reply_markup=get_main_keyboard(user_is_admin))

@bot.message_handler(commands=["admin"])
def cmd_admin(message):
    save_user(message.from_user)
    if not is_admin(message.from_user):
        bot.reply_to(message, "⛔ <b>Доступ запрещён.</b> Вы не являетесь администратором бота.")
        return
    text = get_admin_panel_text(message.from_user)
    bot.send_message(message.chat.id, text, reply_markup=get_admin_keyboard())

@bot.message_handler(commands=["id"])
def cmd_id(message):
    save_user(message.from_user)
    u = message.from_user
    adm = "Да ✅" if is_admin(u) else "Нет ❌"
    text = (
        f"🆔 <b>Информация об аккаунте:</b>\n\n"
        f"• ID: <code>{u.id}</code>\n"
        f"• Username: @{u.username if u.username else 'отсутствует'}\n"
        f"• Имя: {u.first_name or ''} {u.last_name or ''}\n"
        f"• Права администратора: <b>{adm}</b>"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=["broadcast"])
def cmd_broadcast(message):
    save_user(message.from_user)
    if not is_admin(message.from_user):
        bot.reply_to(message, "⛔ <b>Доступ запрещён.</b>")
        return
    
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "⚠️ <b>Использование:</b> <code>/broadcast Ваш текст сообщения</code>")
        return
        
    bcast_text = parts[1]
    user_ids = get_all_user_ids()
    if not user_ids:
        bot.reply_to(message, "⚠️ В базе бота пока нет пользователей для рассылки.")
        return
        
    status_msg = bot.reply_to(message, f"📢 Запуск рассылки для <b>{len(user_ids)}</b> пользователей...")
    success = 0
    failed = 0
    
    for uid in user_ids:
        try:
            bot.send_message(uid, bcast_text)
            success += 1
            time.sleep(0.05)
        except Exception:
            failed += 1
            
    bot.edit_message_text(
        f"✅ <b>Рассылка завершена!</b>\n\n"
        f"• Успешно доставлено: <b>{success}</b>\n"
        f"• Ошибок отправки: <b>{failed}</b>",
        message.chat.id,
        status_msg.message_id
    )

@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    save_user(call.from_user)
    chat_id = call.message.chat.id
    user_is_adm = is_admin(call.from_user)

    # --- ADMIN CALLBACKS ---
    if call.data == "admin_panel":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        text = get_admin_panel_text(call.from_user)
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=get_admin_keyboard())
        bot.answer_callback_query(call.id)

    elif call.data == "admin_clear_cache":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        CACHED_FILE_IDS["apk"] = None
        CACHED_FILE_IDS["antidpi"] = None
        CACHED_FILE_IDS["netmerge"] = None
        bot.answer_callback_query(call.id, "✅ Кэш file_id успешно очищен!", show_alert=True)
        text = get_admin_panel_text(call.from_user)
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=get_admin_keyboard())

    elif call.data == "admin_stats":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        u_count = get_user_count()
        bot.answer_callback_query(call.id, f"👥 Всего пользователей: {u_count}", show_alert=True)

    elif call.data == "admin_check_subs":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        sub_stats = get_sub_stats()
        info = "\n".join([f"• {k}: {v} шт." for k, v in sub_stats.items()])
        bot.answer_callback_query(call.id, f"Подписки Бункера:\n{info}", show_alert=True)

    elif call.data == "admin_list_admins":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        text = (
            "👥 <b>Действующие администраторы @BunkerCatOSBot:</b>\n\n"
            "• 👑 <b>@Titandarkness</b> (ID: <code>5608909722</code>) — Полный доступ\n"
            "• 👑 <b>@k0tlux</b> (ID: <code>6385528140</code>) — Полный доступ"
        )
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("🔙 В админку", callback_data="admin_panel"))
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb)
        bot.answer_callback_query(call.id)

    elif call.data == "admin_broadcast_help":
        if not user_is_adm:
            bot.answer_callback_query(call.id, "⛔ Доступ запрещён!", show_alert=True)
            return
        text = (
            "📢 <b>Рассылка сообщений пользователям:</b>\n\n"
            "Для отправки сообщения всем зарегистрированным пользователям бота отправьте команду:\n\n"
            "<code>/broadcast Ваш текст сообщения</code>\n\n"
            "Поддерживается HTML-разметка форматирования текста."
        )
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("🔙 В админку", callback_data="admin_panel"))
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb)
        bot.answer_callback_query(call.id)

    # --- USER CALLBACKS ---
    elif call.data == "get_apk":
        bot.answer_callback_query(call.id, "Подготавливаю APK Bunker VPN v1.4.9...")
        caption = (
            "⚡ <b>BUNKER VPN v1.4.9 (Android)</b>\n\n"
            "🛡️ <i>Официальный OLED-клиент экосистемы «Бункер Кота»</i>\n\n"
            "🚀 <b>Главные фичи версии v1.4.9:</b>\n"
            "• <b>1-Click Автоподключение:</b> при нажатии на пуск VPN мгновенно выбирает лучший сервер без обязательного тыка в список\n"
            "• <b>Разделение банковских и игровых серверов:</b> каталог «Белый список» переименован в «РФ / Банки», а онлайн-игры (Brawl Stars, Discord) работают через скоростной «Discord / Игры» на Hysteria 2 UDP\n"
            "• <b>Полная совместимость с Android 15–17:</b> стабильный запуск служб и сетевых адаптеров\n"
            "• <b>Стелс-режим / Анти-детект:</b> виртуальный интерфейс <code>bkr0</code> скрыт от антифрода (AppsFlyer, 2GIS, банки)\n"
            "• <b>Фикс Firefox & Chromium в Root:</b> TCP MSS Clamping устраняет зависания на TLS 1.3\n"
            "• <b>Встроенный каталог «YouTube 4K»</b> и база проверенных серверов\n\n"
            "📥 <i>Установите APK поверх или начисто. В шторке фильтров нажмите «Обновить узлы».</i>"
        )
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("🌐 Скачать ARM64 (GitHub)", url=APK_ARM64_URL),
            types.InlineKeyboardButton("📦 Скачать Universal APK (Все архитектуры)", url=APK_UNIVERSAL_URL),
            types.InlineKeyboardButton("⭐ Страница релиза v1.4.9", url=RELEASE_PAGE_URL),
            types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main")
        )
        
        file_sent = False
        if CACHED_FILE_IDS["apk"]:
            try:
                bot.send_document(chat_id, CACHED_FILE_IDS["apk"], caption=caption, reply_markup=kb)
                file_sent = True
            except Exception as e:
                logging.warning(f"Cached APK file_id failed: {e}")
                CACHED_FILE_IDS["apk"] = None

        if not file_sent and os.path.exists(APK_PATH) and os.path.getsize(APK_PATH) > 10 * 1024 * 1024:
            try:
                with open(APK_PATH, "rb") as f:
                    msg = bot.send_document(chat_id, f, visible_file_name="BunkerVPN-v1.4.9-arm64.apk", caption=caption, reply_markup=kb)
                    if msg.document:
                        CACHED_FILE_IDS["apk"] = msg.document.file_id
                file_sent = True
            except Exception as e:
                logging.error(f"Failed to upload APK directly: {e}")

        if not file_sent:
            bot.send_message(chat_id, caption, reply_markup=kb, disable_web_page_preview=True)

    elif call.data == "get_win":
        bot.answer_callback_query(call.id, "Открываю раздел Windows...")
        text = (
            "💻 <b>BUNKER VPN ДЛЯ WINDOWS PC (v1.0.14)</b>\n\n"
            "⚡ Высокоскоростной десктопный клиент обхода блокировок для Windows 10 и 11 (x64):\n\n"
            "• 📺 <b>YouTube 4K Ultra:</b> встроенная подписка без буферизации для 4K/2K 60fps\n"
            "• 🛡️ <b>NCSI Bypass:</b> устранена плашка «Без доступа к Интернету» в трее Windows (Microsoft Store, OneDrive работают штатно)\n"
            "• 🧠 <b>gVisor TUN:</b> надёжный user-space стек без конфликтов с антивирусами\n"
            "• ⚡ <b>VLESS XUDP:</b> Discord Voice и сетевые игры без зависания RTC\n"
            "• 🚀 <b>Live Speedometer:</b> динамический счётчик скорости скачивания/отдачи\n"
            "• 🔪 <b>Copilot Killer:</b> отключение фоновой телеметрии и AI bloatware для экономии ОЗУ\n\n"
            "Выберите удобный вариант загрузки (работает в РФ без VPN):"
        )
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("📥 Установщик Setup (v1.0.14) — Зеркало РФ", url="https://ghfast.top/https://github.com/ANT1VEN0M/BunkerVPN-Windows/releases/download/v1.0.14/BunkerVPN-Windows-v1.0.14-Setup.exe"),
            types.InlineKeyboardButton("🧰 Портативная версия ZIP (v1.0.14) — Зеркало РФ", url="https://ghfast.top/https://github.com/ANT1VEN0M/BunkerVPN-Windows/releases/download/v1.0.14/BunkerVPN-Windows-v1.0.14-Portable.zip"),
            types.InlineKeyboardButton("🐙 GitHub Релиз (Официальный)", url="https://github.com/ANT1VEN0M/BunkerVPN-Windows/releases/tag/v1.0.14"),
            types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main")
        )
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb, disable_web_page_preview=True)

    elif call.data == "get_tg_sos":
        bot.answer_callback_query(call.id, "Загружаю живые MTProto-прокси...")
        proxies = get_mtproto_proxies()
        text = (
            "💬 <b>ПОЖАРНЫЕ MTPROTO-ПРОКСИ (TELEGRAM SOS)</b>\n\n"
            "Прямое подключение к Telegram <b>БЕЗ использования VPN</b> на случай, если всё остальное заблокировано.\n\n"
            "Нажмите на любую кнопку ниже — Telegram сам предложит включить прокси в один клик:"
        )
        kb = types.InlineKeyboardMarkup(row_width=1)
        if proxies:
            for i, p_url in enumerate(proxies, 1):
                kb.add(types.InlineKeyboardButton(f"⚡ Подключить MTProto Прокси #{i}", url=p_url))
        else:
            kb.add(types.InlineKeyboardButton("🚀 Подключить резервный MTProto", url="https://t.me/proxy?server=opeenhostings.co.uk&port=443&secret=eef0eeb0bd9adc4fd4a93994ee3b2a216b63646e2e79656b74616e65742e636f6d"))
        
        kb.add(
            types.InlineKeyboardButton("🔄 Обновить список", callback_data="get_tg_sos"),
            types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main")
        )
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb, disable_web_page_preview=True)

    elif call.data == "get_sub":
        text = (
            "⚡ <b>ВЕЧНЫЕ ССЫЛКИ НА ПОДПИСКИ БУНКЕРА (100% ЖИВЫЕ УЗЛЫ)</b>\n\n"
            "Добавьте ссылку в любое приложение (Bunker VPN / Karing / v2rayNG / Happ / NekoBox / Streisand):\n\n"
            "🌐 <b>Микс всех протоколов (56 серверов: Reality, Hy2, Каскады):</b>\n"
            "<code>https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/mix_b64.txt</code>\n"
            "<i>Зеркало РФ:</i> <code>https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/mix_b64.txt</code>\n\n"
            "🛡️ <b>Белый список / РФ Банки (20 серверов: VK/Yandex LTE, РКП):</b>\n"
            "<code>https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/bs_b64.txt</code>\n"
            "<i>Зеркало РФ:</i> <code>https://ghfast.top/https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/bs_b64.txt</code>\n\n"
            "👑 <b>Золотая выборка (Gold VIP):</b>\n"
            "<code>https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/gold_b64.txt</code>\n\n"
            "📺 <b>YouTube 4K Ultra (Прямой обход ТСПУ):</b>\n"
            "<code>https://raw.githubusercontent.com/ANT1VEN0M/Bunker-Auto-Engine/main/sub/youtube_b64.txt</code>\n\n"
            "🍏 <b>Для iPhone (iOS) подключение в 1 клик:</b>\n"
            "<a href='https://ant1ven0m.github.io/Bunker-Auto-Engine/'>Открыть веб-портал Бункера</a>"
        )
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main"))
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb, disable_web_page_preview=True)
        bot.answer_callback_query(call.id)

    elif call.data == "get_netmerge":
        bot.answer_callback_query(call.id, "Отправляю Bunker Net-Merge...")
        caption = (
            "🚀 <b>BUNKER NET-MERGE v1.0 (Windows PC)</b>\n\n"
            "Агрегатор сетевых каналов (Multi-WAN Bonding) — <b>используйте все ваши интернет-подключения одновременно</b>:\n\n"
            "• Кабель Ethernet + Wi-Fi + Мобильный телефон по USB (режим модема)\n"
            "• Суммирует скорость загрузки в <b>Steam, торрентах, IDM и браузере</b>\n"
            "• Автоматическая балансировка потоков и автоопределение адаптеров\n"
            "• 100% бесплатно, без сторонних серверов и без рекламы\n\n"
            "<i>Распакуйте архив и запустите 1_СТАРТ_СКЛЕЙКИ_ИНТЕРНЕТА.cmd</i>"
        )
        file_sent = False
        if CACHED_FILE_IDS["netmerge"]:
            try:
                bot.send_document(chat_id, CACHED_FILE_IDS["netmerge"], caption=caption)
                file_sent = True
            except Exception:
                CACHED_FILE_IDS["netmerge"] = None

        if not file_sent and os.path.exists(NETMERGE_ZIP_PATH):
            try:
                with open(NETMERGE_ZIP_PATH, "rb") as f:
                    msg = bot.send_document(chat_id, f, visible_file_name="Bunker_NetMerge_v1.0.zip", caption=caption)
                    if msg.document:
                        CACHED_FILE_IDS["netmerge"] = msg.document.file_id
                file_sent = True
            except Exception as e:
                logging.error(f"Failed to send NetMerge zip: {e}")

        if not file_sent:
            bot.send_message(chat_id, "Архив временно недоступен. Обратитесь в чат @BUNKER_K0TA")

    elif call.data == "get_antidpi":
        bot.answer_callback_query(call.id, "Отправляю сборку Bunker Anti-DPI...")
        caption = (
            "🛡️ <b>BUNKER ANTI-DPI v1.0 (Windows PC)</b>\n\n"
            "Прямой обход замедления YouTube и блокировок Discord <b>БЕЗ VPN</b>.\n\n"
            "• YouTube в 4K 60fps на полной скорости провайдера\n"
            "• Discord Голос + Стримы работают\n"
            "• Не грузит систему, автозапуск тихой службы\n\n"
            "<i>Распакуйте архив и запустите BUNKER_START.cmd от имени Администратора.</i>"
        )
        file_sent = False
        if CACHED_FILE_IDS["antidpi"]:
            try:
                bot.send_document(chat_id, CACHED_FILE_IDS["antidpi"], caption=caption)
                file_sent = True
            except Exception:
                CACHED_FILE_IDS["antidpi"] = None

        if not file_sent and os.path.exists(ANTIDPI_ZIP_PATH):
            try:
                with open(ANTIDPI_ZIP_PATH, "rb") as f:
                    msg = bot.send_document(chat_id, f, visible_file_name="Bunker_AntiDPI_v1.0.zip", caption=caption)
                    if msg.document:
                        CACHED_FILE_IDS["antidpi"] = msg.document.file_id
                file_sent = True
            except Exception as e:
                logging.error(f"Failed to send AntiDPI zip: {e}")

        if not file_sent:
            bot.send_message(chat_id, "Архив временно недоступен. Скачайте в канале: @BUNKER_KOTA/1181")

    elif call.data == "get_donate":
        text = (
            "💖 <b>ПОДДЕРЖАТЬ ПРОЕКТ «БУНКЕР КОТА»</b>\n\n"
            "Бункер всегда был и остаётся бесплатным народным проектом.\n"
            "Все средства идут на поддержание парсеров, серверов тестирования и разработку новых утилит обхода.\n\n"
            "👉 <b><a href='" + OZON_SBP_LINK + "'>СБП перевод в 1 клик (Озон Банк)</a></b>\n"
            "<i>(Любая комфортная сумма: 150 ₽, 300 ₽, 500 ₽)</i>\n\n"
            "Каждому, кто поддерживает проект — искреннее спасибо и личный респект от @k0tlux! 🫡"
        )
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("💳 Перевести по СБП (Озон Банк)", url=OZON_SBP_LINK))
        kb.add(types.InlineKeyboardButton("🔙 В главное меню", callback_data="back_main"))
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=kb)
        bot.answer_callback_query(call.id)

    elif call.data == "back_main":
        user_name = call.from_user.first_name or "друг"
        admin_badge = " [👑 Администратор]" if user_is_adm else ""
        text = (
            f"🐈‍⬛ <b>Салют, {user_name}!{admin_badge}</b>\n\n"
            f"Добро пожаловать в официальный бот экосистемы <b>«Бункер Кота»</b> (1400+ участников).\n\n"
            f"<i>Выбери нужный раздел:</i>"
        )
        bot.edit_message_text(text, chat_id, call.message.message_id, reply_markup=get_main_keyboard(user_is_adm))
        bot.answer_callback_query(call.id)

if __name__ == "__main__":
    init_db()
    logging.info("Starting BunkerCatOSBot polling with Admin Rights configured for @Titandarkness and @k0tlux...")
    while True:
        try:
            bot.infinity_polling(timeout=20, long_polling_timeout=20)
        except Exception as e:
            logging.error(f"Bot polling error: {e}")
            time.sleep(5)
