import re
import os
import json
import shutil
import tempfile
import subprocess
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

# مسیر فایل اجرایی Xray (اگر در PATH نیست، مسیر کامل را بدهید؛ مثلاً ./xray)
XRAY_PATH = shutil.which("xray") or "./xray"
SPEED_TEST_WORKERS = 5    # برای ترموکس کم نگه داشته شده
TCP_TEST_WORKERS = 50     # برای ترموکس کم نگه داشته شده
SPEED_TEST_TIMEOUT = 15   # ثانیه

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

        for future in concurrent.futures.as_completed(future_to_config):
            result = future.result()
            if result['status']:
                alive_configs.append(result['config'])

    print(f"{Colors.GREEN}✅ تست TCP تمام شد. تعداد {len(alive_configs)} کانفیگ زنده و پاسخگو ماندند.{Colors.RESET}")
    return alive_configs

# ==========================================
# ۲. تست سرعت واقعی (هر کانفیگ با یک پروسه Xray جداگانه)
# ==========================================
def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def build_xray_config(config_url, local_port):
    """لینک vless را به کانفیگ JSON مخصوص Xray تبدیل می‌کند (inbound: socks محلی)."""
    p = urlparse(config_url)
    q = {k.lower(): unquote(v[0]) for k, v in parse_qs(p.query).items()}

    net = q.get('type', 'tcp').lower()
    net = {'h2': 'http', 'splithttp': 'xhttp', 'raw': 'tcp'}.get(net, net)
    security = q.get('security', 'none').lower()
    host_hdr = q.get('host', '')
    path = q.get('path', '/')

    user = {"id": unquote(p.username), "encryption": q.get('encryption', 'none')}
    if q.get('flow'):
        user["flow"] = q['flow']

    stream = {"network": net, "security": security if security != 'xtls' else 'tls'}

    if net == 'tcp' and q.get('headertype') == 'http':
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [h for h in host_hdr.split(',') if h]}}}}
    elif net == 'ws':
        ws = {"path": path}
        if host_hdr:
            ws["headers"] = {"Host": host_hdr}
        stream["wsSettings"] = ws
    elif net == 'grpc':
        stream["grpcSettings"] = {"serviceName": q.get('servicename', ''),
                                  "multiMode": q.get('mode') == 'multi'}
    elif net == 'httpupgrade':
        stream["httpupgradeSettings"] = {"path": path, "host": host_hdr}
    elif net == 'xhttp':
        stream["xhttpSettings"] = {"path": path, "host": host_hdr, "mode": q.get('mode', 'auto')}
    elif net == 'kcp':
        stream["kcpSettings"] = {"header": {"type": q.get('headertype', 'none')},
                                 "seed": q.get('seed', '')}
    elif net == 'http':
        stream["httpSettings"] = {"path": path, "host": [h for h in host_hdr.split(',') if h]}

    sni = q.get('sni', '') or host_hdr
    if security in ('tls', 'xtls'):
        tls = {"serverName": sni, "allowInsecure": q.get('allowinsecure', '0') in ('1', 'true')}
        if q.get('fp'):
            tls["fingerprint"] = q['fp']
        if q.get('alpn'):
            tls["alpn"] = q['alpn'].split(',')
        stream["tlsSettings"] = tls
    elif security == 'reality':
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": q.get('fp', 'chrome'),
            "publicKey": q.get('pbk', ''),
            "shortId": q.get('sid', ''),
            "spiderX": q.get('spx', ''),
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": local_port, "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": p.hostname, "port": p.port, "users": [user]}]},
            "streamSettings": stream
        }]
    }

def test_download_speed(config_url):
    """کانفیگ را با Xray روی یک پورت اختصاصی بالا می‌آورد و ۱ مگابایت دانلود می‌کند."""
    failed = {'config': config_url, 'speed': 0, 'status': 'failed'}
    proc, cfg_path = None, None
    try:
        port = get_free_port()
        xray_cfg = build_xray_config(config_url, port)

        fd, cfg_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(xray_cfg, f)

        proc = subprocess.Popen([XRAY_PATH, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # صبر تا باز شدن پورت محلی SOCKS
        ready = False
        for _ in range(30):
            if proc.poll() is not None:
                return failed
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        if not ready:
            return failed

        proxy = f"socks5h://127.0.0.1:{port}"
        start = time.time()
        r = requests.get("http://speedtest.tele2.net/1MB.zip",
                         proxies={"http": proxy, "https": proxy}, timeout=SPEED_TEST_TIMEOUT)
        duration = time.time() - start
        if r.status_code == 200 and len(r.content) >= 1000000 and duration > 0:
            return {'config': config_url, 'speed': (1.0 / duration) * 8, 'status': 'ok'}
    except Exception:
        pass
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        if cfg_path and os.path.exists(cfg_path):
            os.remove(cfg_path)
    return failed

def filter_top_configs(tcp_alive_configs):
    if not tcp_alive_configs:
        return []

    if not (shutil.which(XRAY_PATH) or os.path.isfile(XRAY_PATH)):
        print(f"{Colors.RED}❌ فایل Xray در مسیر '{XRAY_PATH}' پیدا نشد؛ تست سرعت انجام نشد و فقط نتیجه TCP استفاده می‌شود.{Colors.RESET}")
        return tcp_alive_configs[:MAX_FINAL_CONFIGS]

    print(f"\n{Colors.YELLOW}🚀 شروع تست سرعت واقعی (۱ مگابایت، با Xray) روی {len(tcp_alive_configs)} کانفیگ...{Colors.RESET}")

    valid_tested = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=SPEED_TEST_WORKERS) as executor:
        futures = [executor.submit(test_download_speed, url) for url in tcp_alive_configs]
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            if result['status'] == 'ok':
                valid_tested.append(result)
            if done % 50 == 0:
                print(f"   ... {done}/{len(futures)} تست شد، {len(valid_tested)} موفق")

    if not valid_tested:
        print(f"{Colors.YELLOW}⚠️ هیچ کانفیگی در تست سرعت موفق نبود. استفاده از کانفیگ‌های تایید شده TCP.{Colors.RESET}")
        return tcp_alive_configs[:MAX_FINAL_CONFIGS]

    valid_tested.sort(key=lambda x: x['speed'], reverse=True)
    top = valid_tested[:MAX_FINAL_CONFIGS]

    print(f"{Colors.GREEN}✅ گلچین کردن {len(top)} کانفیگ پرسرعت انجام شد.{Colors.RESET}")
    return [item['config'] for item in top]

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

        if tcp_alive_configs:
            # مرحله ۲: تست سرعت دانلود و گلچین کردن کانفیگ‌های برتر
            best_configs = filter_top_configs(tcp_alive_configs)
        else:
            best_configs = []

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

            print(f"\n{Colors.GREEN}✅ فایل نهایی سابسکریپشن با {len(best_configs)} کانفیگ سالم و پرسرعت ساخته شد!{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}❌ هیچ کانفیگی از تست TCP یا سرعت عبور نکرد.{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}❌ هیچ کانفیگ استانداردی یافت نشد.{Colors.RESET}")

if __name__ == "__main__":
    scrape_all_channels()
