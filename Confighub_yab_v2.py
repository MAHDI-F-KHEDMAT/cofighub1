import re
import os
import time
import html
import base64
import socket
import requests
import urllib.parse
import concurrent.futures
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone

# فهماندن پروتکل vless به کتابخانه استاندارد پایتون
urllib.parse.uses_netloc.append('vless')

# ==========================================
# ⚙️ تنظیمات اسکریپت
# ==========================================
DAYS_BACK = 2
CONFIG_PREFIX_NAME = "ConfigsHUB_VIP_"
MAX_FINAL_CONFIGS = 500  # محدودیت فایل نهایی (کانفیگ‌های برتر)

TCP_TEST_WORKERS = 50     # برای ترموکس کم نگه داشته شده

CHANNELS = [
    "https://t.me/ConfigsHUB"
]

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

# هر پرینت بلافاصله نمایش داده شود و زمان هم داشته باشد
_builtin_print = print
def print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    _builtin_print(datetime.now().strftime("[%H:%M:%S]"), *args, **kwargs)

def short(url, n=45):
    """نمایش کوتاه‌شده‌ی کانفیگ در لاگ"""
    p = urlparse(url)
    return f"{p.hostname}:{p.port}" if p.hostname else url[:n]

# ==========================================
# ۱. تابع تست اتصال TCP سریع (فیلتر اولیه سلامت هاست و پورت)
# ==========================================
def check_tcp_connection(config_url, timeout=3):
    try:
        parsed = urlparse(config_url)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return {'config': config_url, 'status': False}

        with socket.create_connection((host, port), timeout=timeout):
            return {'config': config_url, 'status': True}
    except Exception:
        return {'config': config_url, 'status': False}

def filter_tcp_alive_configs(unique_configs):
    print(f"\n{Colors.YELLOW}⚡ شروع تست اتصال TCP سریع برای {len(unique_configs)} کانفیگ...{Colors.RESET}")

    alive_configs = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_TEST_WORKERS) as executor:
        future_to_config = {executor.submit(check_tcp_connection, url): url for url in unique_configs}

        total = len(future_to_config)
        for done, future in enumerate(concurrent.futures.as_completed(future_to_config), 1):
            result = future.result()
            if result['status']:
                alive_configs.append(result['config'])
                print(f"   [TCP {done}/{total}] {Colors.GREEN}زنده{Colors.RESET}  {short(result['config'])}  (جمع زنده: {len(alive_configs)})")
            else:
                print(f"   [TCP {done}/{total}] {Colors.RED}مرده{Colors.RESET}  {short(result['config'])}")

    print(f"{Colors.GREEN}✅ تست TCP تمام شد. تعداد {len(alive_configs)} کانفیگ زنده و پاسخگو ماندند.{Colors.RESET}")
    return alive_configs

# ==========================================
# ۳. تابع فیلتر ضد کرش ساختاری
# ==========================================
def is_bulletproof_vless(raw_url):
    try:
        parsed = urlparse(raw_url)
        if not parsed.hostname or not parsed.port: return False
        if not (1 <= parsed.port <= 65535): return False
        qs = parse_qs(parsed.query)
        params = {k.lower(): v[0] for k, v in qs.items()}
        net_type, security, flow = params.get('type', 'tcp').lower(), params.get('security', 'none').lower(), params.get('flow', '').lower()
        if security not in ('none', 'tls', 'xtls', 'reality'): return False
        if security == 'reality':
            if not params.get('pbk', '') or not re.match(r'^[A-Za-z0-9\-_]{43}$', params.get('pbk', '')): return False
            if params.get('sid', '') and not re.match(r'^([0-9a-fA-F]{2}){1,8}$', params.get('sid', '')): return False
            if not params.get('sni', ''): return False
        if 'vision' in flow and (net_type != 'tcp' or security not in ('tls', 'xtls', 'reality')): return False
        return True
    except Exception: return False

# ==========================================
# ۴. تابع بررسی هر کانال
# ==========================================
def scrape_channel(channel_url, cutoff_datetime, session, config_pattern):
    if "/s/" not in channel_url: channel_url = channel_url.replace("t.me/", "t.me/s/")
    current_url, reached_old, channel_configs, seen_min_ids = channel_url, False, [], set()

    print(f"\n" + "─" * 60)
    print(f"📂 شروع بررسی کانال: {channel_url}")
    print("─" * 60)

    while not reached_old:
        try:
            response = session.get(current_url, timeout=25)
            if response.status_code == 429:
                time.sleep(15)
                continue
            if response.status_code != 200:
                print(f"{Colors.RED}❌ کد پاسخ: {response.status_code}{Colors.RESET}")
                break
        except Exception as e:
            print(f"{Colors.RED}❌ خطای شبکه: {e}{Colors.RESET}")
            break

        soup = BeautifulSoup(response.text, 'html.parser')
        messages = soup.find_all('div', class_='tgme_widget_message')
        if not messages:
            print(f"{Colors.YELLOW}⚠️ پیامی در صفحه پیدا نشد.{Colors.RESET}")
            break

        page_min_id = None
        for msg in messages:
            data_post = msg.get('data-post', '')
            if '/' in data_post:
                try:
                    msg_id = int(data_post.split('/')[-1])
                    if page_min_id is None or msg_id < page_min_id: page_min_id = msg_id
                except ValueError: pass

            # فقط تگ time که واقعاً ویژگی datetime دارد
            time_tag = msg.find('time', attrs={'datetime': True})
            if not time_tag: continue

            try:
                msg_dt = datetime.fromisoformat(time_tag['datetime'].replace('Z', '+00:00').split('+')[0])
            except (ValueError, TypeError, AttributeError): continue

            if msg_dt < cutoff_datetime:
                reached_old = True
                break

            text_div = msg.find('div', class_='tgme_widget_message_text') or msg.find('div', class_='tgme_widget_message_caption')
            if text_div:
                msg_text = html.unescape(text_div.get_text(separator=" ", strip=False))
                for raw_config in config_pattern.findall(msg_text):
                    if is_bulletproof_vless(raw_config):
                        channel_configs.append(raw_config)

        print(f"   صفحه بررسی شد؛ تا اینجا {len(channel_configs)} کانفیگ")

        if reached_old or not page_min_id or page_min_id in seen_min_ids: break
        seen_min_ids.add(page_min_id)
        current_url = f"{channel_url}?before={page_min_id}"
        time.sleep(1.5)
    return channel_configs

# ==========================================
# ۵. مدیریت اصلی
# ==========================================
def scrape_all_channels():
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"})
    cutoff_datetime = (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).replace(tzinfo=None)
    config_pattern = re.compile(r'vless://[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@[^\s\'"<>#]+')

    all_extracted_configs = []
    for channel in CHANNELS:
        try:
            all_extracted_configs.extend(scrape_channel(channel, cutoff_datetime, session, config_pattern))
        except Exception as e:
            print(f"{Colors.RED}❌ خطا: {e}{Colors.RESET}")

    unique_configs = list(dict.fromkeys(all_extracted_configs))

    if unique_configs:
        # مرحله ۱: تست اتصال TCP سریع برای حذف کانفیگ‌های مرده
        tcp_alive_configs = filter_tcp_alive_configs(unique_configs)

        best_configs = tcp_alive_configs[:MAX_FINAL_CONFIGS]

        if best_configs:
            renamed_list = []
            for idx, config in enumerate(best_configs, 1):
                new_name = f"{CONFIG_PREFIX_NAME}{idx}"
                renamed_list.append(f"{config}#{new_name}")

            plain_text_content = "\n".join(renamed_list)
            b64_encoded_content = base64.b64encode(plain_text_content.encode('utf-8')).decode('utf-8')

            sub_filename = 'sub_vless_base64.txt'
            with open(sub_filename, 'w', encoding='utf-8') as f:
                f.write(b64_encoded_content)

            print(f"\n{Colors.GREEN}✅ فایل نهایی سابسکریپشن با {len(best_configs)} کانفیگ سالم ساخته شد!{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}❌ هیچ کانفیگی از تست TCP عبور نکرد.{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}❌ هیچ کانفیگ استانداردی یافت نشد.{Colors.RESET}")

if __name__ == "__main__":
    scrape_all_channels()
