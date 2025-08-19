import asyncio
import httpx
import time
import hashlib
import json
import random
import sys
import io
import logging
from datetime import datetime
from pytz import timezone
from urllib.parse import quote

# Buộc sử dụng mã hóa UTF-8 cho đầu ra console
if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()
logging.getLogger("httpx").setLevel(logging.WARNING)

# Danh sách tỉnh toàn cục
provinces = []

# Trạng thái tài khoản
class AccountState:
    def __init__(self):
        self.is_first_run = True
        self.account_nick = None
        self.share_count = 0
        self.max_shares = 999999999
        self.token = None

async def safe_request(client, method, url, **kwargs):
    """Gửi request với cơ chế thử lại"""
    for attempt in range(5):
        try:
            if method == "POST":
                resp = await client.post(url, **kwargs)
                data = resp.json()
            else:
                resp = await client.get(url, **kwargs)
            resp.raise_for_status()
            return resp
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"Lỗi request {url} (lần {attempt+1}): {e}")
            await asyncio.sleep(1)
    logger.error(f"Thất bại request {url} sau 5 lần thử")
    return None

async def login(client: httpx.AsyncClient, key, account):
    """Đăng nhập để lấy token và cookie, bao gồm cả API account-login và UserInfo"""
    try:
        headers = {
            'origin': 'https://au.vtc.vn',
            'referer': 'https://au.vtc.vn',
            'sec-ch-ua': '"Android WebView";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'
        }
        
        resp = await safe_request(client, "POST", 'https://au.vtc.vn/header/Handler/Process.ashx?act=GetCookieAuthString', data=f'info={quote(key)}', headers=headers)
        if not resp:
            logger.warning(f"Thất bại lấy CookieAuthString sau 5 lần thử: {account}")
            return None, None
        if resp.status_code == 200:
            data = resp.json()
            if data['ResponseStatus'] != 1:
                logger.warning(f'Đăng nhập thất bại: {account}')
                return None, None
        else:
            logger.warning(f'Lỗi đăng nhập {account}: HTTP {resp.status_code}')
            return None, None
        
        resp = await safe_request(client, "GET", 'https://au.vtc.vn/bsau', headers=headers)
        if not resp:
            logger.warning(f"Thất bại lấy token sau 5 lần thử: {account}")
            return None, None
        if resp.status_code == 200:
            data = resp.text
            try:
                token_value = data.split('\\"tokenValue\\":\\"')[1].split('\\"')[0]
                client.cookies.set('vtc-jwt', token_value, domain='au.vtc.vn', path='/')
                cookies = {
                    'vtc-jwt': token_value,
                    'auvtc.vn': client.cookies.get('auvtc.vn', domain='.vtc.vn'),
                    'ASP.NET_SessionId': client.cookies.get('ASP.NET_SessionId', domain='au.vtc.vn')
                }
                logger.info(f"Tài khoản {account}: Đã đăng nhập thành công, vtc-jwt được đặt từ token_value")
                if not cookies['auvtc.vn']:
                    logger.warning(f"Tài khoản {account}: Không tìm thấy cookie auvtc.vn trong phản hồi")
                return token_value, cookies
            except IndexError:
                logger.warning(f'Lỗi phân tích token: {account}')
                return None, None
        else:
            logger.warning(f'Lỗi lấy token {account}: HTTP {resp.status_code}')
            return None, None
    
    except Exception as e:
        logger.error(f'Lỗi đăng nhập {account}: {e}')
        return None, None

async def get_cookies(client: httpx.AsyncClient, username, login_cookies):
    """Gọi API get-cookies để lấy cookie"""
    try:
        cookies = {
            "_ga": "GA1.1.475682509.1755535140",
            "AuthenTypeAU": "0",
            "isRemember": "False",
            "_ga_ZF7B4XDHMY": "GS2.1.s1755538911`$o2`$g1`$t1755540884`$j56`$l0`$h0",
        }
        if login_cookies.get('vtc-jwt'):
            cookies['vtc-jwt'] = login_cookies['vtc-jwt']
        if login_cookies.get('auvtc.vn'):
            cookies['auvtc.vn'] = login_cookies['auvtc.vn']
        if login_cookies.get('ASP.NET_SessionId'):
            cookies['ASP.NET_SessionId'] = login_cookies['ASP.NET_SessionId']

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": "https://au.vtc.vn/bsau",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"'
        }

        resp = await safe_request(client, "GET", "https://au.vtc.vn/bsau/api/get-cookies", headers=headers, cookies=cookies)
        if not resp:
            logger.warning(f"Tài khoản {username}: Thất bại khi gọi API get-cookies")
            return False
        data = resp.json()    
        if data:
            if data.get("code") == 1:
                logger.info(f"Tài khoản {username}: get-cookies thành công!")
            else:
                logger.warning(f"Tài khoản {username}: get-cookies thất bại!")
        else:
            logger.info(f"Tài khoản {username} không nhận được dữ liệu Mã lỗi: {data.get('code')}")

        return True

    except Exception as e:
        logger.error(f"Tài khoản {username}: Lỗi khi gọi API get-cookies: {e}")
        return False

async def run_event_flow(username, key, state):
    """Chạy luồng sự kiện cho một tài khoản với client riêng"""
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1, keepalive_expiry=0)
    async with httpx.AsyncClient(timeout=3.0, http2=False, limits=limits) as client:
        retry_count = 0
        max_retries = 10
        while retry_count < max_retries:
            try:
                if state.share_count >= state.max_shares:
                    logger.info(f"Tài khoản {username}: Đã đạt giới hạn share ({state.share_count}/{state.max_shares})")
                    return False

                if state.is_first_run:
                    token, login_cookies = await login(client, key, username)
                    if not token or not login_cookies:
                        logger.error(f"Không thể lấy token hoặc cookie cho tài khoản {username}")
                        return False
                    state.token = token
                    state.account_nick = username
                    state.is_first_run = True

                bearer_token = f"Bearer {state.token}"

                maker_code = "BEAuSN19"
                backend_key_sign = "de54c591d457ed1f1769dda0013c9d30f6fc9bbff0b36ea0a425233bd82a1a22"
                login_url = "https://apiwebevent.vtcgame.vn/besnau19/Event"
                au_url = "https://au.vtc.vn"

                def get_current_timestamp():
                    return int(time.time())

                def sha256_hex(data):
                    return hashlib.sha256(data.encode('utf-8')).hexdigest()

                async def generate_sign(ts, func):
                    raw = f"{ts}{maker_code}{func}{backend_key_sign}"
                    return sha256_hex(raw)

                browser_headers = { 
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Referer": "https://au.vtc.vn/",
                    "Accept-Language": "en-US,en;q=0.9,vi;q=0.8", 
                }

                mission_headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/plain, */*",
                    "Authorization": bearer_token,
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": au_url
                }

                if not await get_cookies(client, username, login_cookies):
                    logger.warning(f"Tài khoản {username}: Không thể tiếp tục do lỗi get-cookies")
                    state.is_first_run = True
                    retry_count += 1
                    await asyncio.sleep(2)
                    continue

                async def send_wish(account_nick):
                    global provinces
                    if not provinces:
                        logger.info(f"Tài khoản {account_nick}: Lấy danh sách tỉnh...")
                        ts = get_current_timestamp()
                        sign = await generate_sign(ts, "wish-get-list")
                        payload = {
                            "time": ts,
                            "fromIP": "",
                            "sign": sign,
                            "makerCode": maker_code,
                            "func": "wish-get-list",
                            "data": ""
                        }
                        resp = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
                        if not resp:
                            return None, None
                        data = resp.json()
                        if data.get("code") != 1:
                            logger.warning(f"Tài khoản {account_nick}: Lấy danh sách tỉnh thất bại. Mã lỗi: {data.get('code')}")
                            return None, data.get("code")
                        provinces = data["data"]["list"]
                        logger.info(f"Tài khoản {account_nick}: Có {len(provinces)} tỉnh.")

                    if not provinces:
                        return None, None

                    selected = random.choice(provinces)
                    ts = get_current_timestamp()
                    sign = await generate_sign(ts, "wish-send")
                    payload = {
                        "time": ts,
                        "sign": sign,
                        "makerCode": maker_code,
                        "func": "wish-send",
                        "data": {
                            "AuthenType": 0,
                            "ProvinceID": 59,
                            "ProvinceName": "TP.Hồ Chí Minh",
                            "Content": "Thắp sáng bản đồ Việt Nam cùng Audition!"
                        }
                    }
                    resp = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
                    if not resp:
                        return None, None
                    res = resp.json()
                    if res.get("mess") != "Gửi lời chúc thành công!":
                        logger.warning(f"Tài khoản {account_nick}: Gửi lời chúc thất bại. Thông báo: {res.get('mess')}, Mã lỗi: {res.get('code')}")
                        return None, res.get("code")
                    logger.info(f"Tài khoản {username}: Gửi lời chúc thành công! ({selected['ProvinceName']})")
                    return (res["code"], ts), None

                async def perform_share(log_id, account_nick, username, wish_time):
                    share_raw = f"{wish_time}{maker_code}{au_url}{backend_key_sign}"
                    share_sign = sha256_hex(share_raw)
                    share_url = f"{au_url}/bsau/api/generate-share-token?username={username}&time={wish_time}&sign={share_sign}"
                    resp = await safe_request(client, "GET", share_url, headers=browser_headers)
                    if not resp or 'application/json' not in resp.headers.get('Content-Type', ''):
                        logger.warning(f"Tài khoản {account_nick}: Thất bại lấy share token.")
                        return False
                    token_data = resp.json()
                    share_token = token_data.get("token")
                    if not share_token:
                        logger.warning(f"Tài khoản {account_nick}: Không tìm thấy share token trong phản hồi.")
                        return False

                    ts = get_current_timestamp()
                    final_sign = await generate_sign(ts, "wish-share")
                    payload = {
                        "time": ts,
                        "fromIP": "",
                        "sign": final_sign,
                        "makerCode": maker_code,
                        "func": "wish-share",
                        "data": {
                            "LogID": log_id,
                            "key": share_token,
                            "timestamp": wish_time,
                            "a": "aa"
                        }
                    }
                    res = await safe_request(client, "POST", login_url, json=payload, headers=mission_headers)
                    if not res:
                        return False
                    response_data = res.json()
                    logger.info(f"Tài khoản {account_nick}: Kết quả share: {response_data}")
                    if response_data.get("code") == 1:
                        return True
                    else:
                        logger.warning(f"Tài khoản {account_nick}: Share thất bại. Mã lỗi: {response_data.get('code')}")
                        return False

                result, error_code = await send_wish(state.account_nick)
                if not result:
                    # if error_code == -99:
                        # logger.info(f"Tài khoản {username}: Gặp mã lỗi -99, đặt lại trạng thái và thử lại")
                        # state.is_first_run = True
                        # retry_count += 1
                        # await asyncio.sleep(2)
                        # continue
                    return False
                log_id, wish_time = result

                if await perform_share(log_id, state.account_nick, username, wish_time):
                    state.share_count += 1
                    logger.info(f"Tài khoản {username}: Đã share thành công. Tổng share: {state.share_count}")
                    return True
                return False

            except Exception as e:
                logger.error(f"Lỗi tổng quát cho tài khoản {username}: {e}")
                retry_count += 1
                state.is_first_run = True
                await asyncio.sleep(10)
                continue

        logger.error(f"Tài khoản {username}: Đã thử lại {max_retries} lần nhưng vẫn thất bại")
        return False

async def load_accounts():
    """Tải tài khoản và key từ file account.txt"""
    accounts = []
    try:
        with open('account.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split('|')
                    if len(parts) != 2:
                        logger.error(f"Dòng không hợp lệ trong account.txt: {line.strip()}")
                        continue
                    account, encoded_key = parts
                    try:
                        key = bytes.fromhex(encoded_key).decode('utf-8')
                        accounts.append((account, key))
                    except Exception as e:
                        logger.error(f"Lỗi giải mã key cho tài khoản {account}: {e}")
    except Exception as e:
        logger.error(f"Lỗi đọc file account.txt: {e}")
    return accounts

# Thêm biến toàn cục để đếm tổng số share
total_shares = 0

async def main():
    global total_shares
    accounts = await load_accounts()
    if not accounts:
        logger.error("Không có tài khoản nào để xử lý.")
        return

    sem = asyncio.Semaphore(2)
    states = {u: AccountState() for u, k in accounts}

    async def process_account(username, key, state):
        global total_shares
        async with sem:
            ok = await run_event_flow(username, key, state)
            await asyncio.sleep(2)
            return ok

    try:
        while True:
            logger.info("Bắt đầu xử lý từ đầu danh sách tài khoản")
            tasks = [process_account(u, k, states[u]) for u, k in accounts]
            await asyncio.gather(*tasks)
            logger.info("Đã xử lý xong tất cả tài khoản, quay lại từ đầu")
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Nhận tín hiệu dừng, đang thoát...")

if __name__ == "__main__":
    asyncio.run(main())