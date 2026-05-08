#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选域名探测脚本 - 增强修正版
✅ 纯Python原生探测（socket+ssl），跨平台兼容
✅ 修复 HEAD→GET 405 问题
✅ 修复 full 模式 colo 缺失导致区域筛选失效
✅ 修复 0.0 延迟被误判为 False 的漏计问题
✅ 优化 Socket 关闭逻辑，避免 RST 噪声日志
✅ 收紧 tcp_loss/tls_loss 评分阈值
✅ 增加 full 模式配置完整性校验
"""
import threading
import queue
import random
import time
import sys
import os
import json
import subprocess
import shutil
import re
import socket
import urllib.request
import ssl
import concurrent.futures
from datetime import datetime
from pathlib import Path

# ================= 路径与文件 =================
BASE_DIR = Path(__file__).resolve().parent
def get_today():
    return datetime.now().strftime("%Y%m%d")
LOG_FILE = BASE_DIR / f"{get_today()}_cf_test.log"
HIT_FILE = BASE_DIR / f"{get_today()}_cf_hits.csv"

# ================= 配置导入 =================
from config import *

# ================= 平台检测 =================
def detect_platform():
    if Path("/etc/openwrt_release").exists(): return "istoreos"
    s = sys.platform
    if s == "win32": return "windows"
    if s == "darwin": return "macos"
    return "linux"
PLATFORM = detect_platform()
CONCURRENCY = {"istoreos": 8, "windows": 10, "macos": 10, "linux": 10}.get(PLATFORM, 2)

# ================= 正则 =================
IP_RE = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')

# ================= colo 映射 =================
COLO_NAME = {
    "PEK": "Beijing", "PKX": "Beijing Daxing", "PVG": "Shanghai Pudong", "SHA": "Shanghai Hongqiao",
    "CAN": "Guangzhou", "SZX": "Shenzhen", "CTU": "Chengdu", "HGH": "Hangzhou",
    "NKG": "Nanjing", "WUH": "Wuhan", "XIY": "Xi'an", "CKG": "Chongqing",
    "TSN": "Tianjin", "DLC": "Dalian", "TAO": "Qingdao", "XMN": "Xiamen",
    "FOC": "Fuzhou", "CSX": "Changsha", "KMG": "Kunming", "URC": "Urumqi",
    "HKG": "Hong Kong", "MFM": "Macau", "TPE": "Taipei", "TSA": "Taipei Songshan",
    "NRT": "Tokyo", "HND": "Tokyo Haneda", "KIX": "Osaka", "NGO": "Nagoya", "FUK": "Fukuoka", "CTS": "Sapporo",
    "ICN": "Seoul", "GMP": "Seoul Gimpo", "PUS": "Busan", "SIN": "Singapore",
    "LAX": "Los Angeles", "SFO": "San Francisco", "SJC": "San Jose", "OAK": "Oakland",
    "SEA": "Seattle", "PDX": "Portland", "SAN": "San Diego",
    "DFW": "Dallas", "DEN": "Denver", "PHX": "Phoenix", "LAS": "Las Vegas",
    "ORD": "Chicago", "MSP": "Minneapolis", "DTW": "Detroit",
    "ATL": "Atlanta", "MIA": "Miami", "IAD": "Washington DC",
    "EWR": "New York", "BOS": "Boston", "PHL": "Philadelphia", "CLT": "Charlotte", "MCO": "Orlando",
    "YVR": "Vancouver", "YYZ": "Toronto", "YUL": "Montreal", "HNL": "Honolulu",
    "LHR": "London", "CDG": "Paris", "FRA": "Frankfurt", "AMS": "Amsterdam", "MAD": "Madrid",
    "DUB": "Dublin", "BRU": "Brussels", "ZRH": "Zurich", "VIE": "Vienna",
    "CPH": "Copenhagen", "ARN": "Stockholm", "OSL": "Oslo", "HEL": "Helsinki",
    "WAW": "Warsaw", "PRG": "Prague", "BUD": "Budapest",
    "ATH": "Athens", "IST": "Istanbul", "MXP": "Milan", "FCO": "Rome",
    "BCN": "Barcelona", "LIS": "Lisbon",
    "BKK": "Bangkok", "KUL": "Kuala Lumpur", "MNL": "Manila", "SGN": "Ho Chi Minh City",
    "CGK": "Jakarta", "DPS": "Bali", "HAN": "Hanoi",
    "BOM": "Mumbai", "DEL": "New Delhi", "MAA": "Chennai", "BLR": "Bangalore",
    "DXB": "Dubai", "AUH": "Abu Dhabi", "DOH": "Doha",
    "RUH": "Riyadh", "JED": "Jeddah", "TLV": "Tel Aviv",
    "JNB": "Johannesburg", "CPT": "Cape Town", "CAI": "Cairo", "LOS": "Lagos",
    "NBO": "Nairobi", "ADD": "Addis Ababa", "CMN": "Casablanca",
    "GRU": "Sao Paulo", "GIG": "Rio de Janeiro", "EZE": "Buenos Aires", "SCL": "Santiago",
    "LIM": "Lima", "BOG": "Bogota", "SYD": "Sydney", "MEL": "Melbourne",
    "BNE": "Brisbane", "PER": "Perth", "AKL": "Auckland", "WLG": "Wellington",
}
REGION_MAP = {
    "HKG": "HONGKONG", "MFM": "HONGKONG",
    "TPE": "EastAsia", "TSA": "EastAsia", "NRT": "EastAsia", "HND": "EastAsia", "KIX": "EastAsia",
    "NGO": "EastAsia", "FUK": "EastAsia", "CTS": "EastAsia", "ICN": "EastAsia", "GMP": "EastAsia",
    "PUS": "EastAsia", "SIN": "EastAsia",
    "LAX": "NorthAmerica", "SFO": "NorthAmerica", "SJC": "NorthAmerica", "OAK": "NorthAmerica",
    "SEA": "NorthAmerica", "PDX": "NorthAmerica", "SAN": "NorthAmerica", "DFW": "NorthAmerica",
    "DEN": "NorthAmerica", "PHX": "NorthAmerica", "LAS": "NorthAmerica", "ORD": "NorthAmerica",
    "MSP": "NorthAmerica", "DTW": "NorthAmerica", "ATL": "NorthAmerica", "MIA": "NorthAmerica",
    "IAD": "NorthAmerica", "EWR": "NorthAmerica", "BOS": "NorthAmerica", "PHL": "NorthAmerica",
    "CLT": "NorthAmerica", "MCO": "NorthAmerica", "YVR": "NorthAmerica", "YYZ": "NorthAmerica",
    "YUL": "NorthAmerica", "HNL": "NorthAmerica",
    "LHR": "Europe", "CDG": "Europe", "FRA": "Europe", "AMS": "Europe", "MAD": "Europe",
    "DUB": "Europe", "BRU": "Europe", "ZRH": "Europe", "VIE": "Europe", "CPH": "Europe",
    "ARN": "Europe", "OSL": "Europe", "HEL": "Europe", "WAW": "Europe", "PRG": "Europe",
    "BUD": "Europe", "ATH": "Europe", "IST": "Europe", "MXP": "Europe", "FCO": "Europe",
    "BCN": "Europe", "LIS": "Europe",
    "BKK": "SoutheastAsia", "KUL": "SoutheastAsia", "MNL": "SoutheastAsia", "SGN": "SoutheastAsia",
    "CGK": "SoutheastAsia", "DPS": "SoutheastAsia", "HAN": "SoutheastAsia",
    "BOM": "SoutheastAsia", "DEL": "SoutheastAsia", "MAA": "SoutheastAsia", "BLR": "SoutheastAsia",
    "DXB": "MiddleEast", "AUH": "MiddleEast", "DOH": "MiddleEast", "RUH": "MiddleEast",
    "JED": "MiddleEast", "TLV": "MiddleEast",
    "JNB": "Africa", "CPT": "Africa", "CAI": "Africa", "LOS": "Africa",
    "NBO": "Africa", "ADD": "Africa", "CMN": "Africa",
    "GRU": "SouthAmerica", "GIG": "SouthAmerica", "EZE": "SouthAmerica", "SCL": "SouthAmerica",
    "LIM": "SouthAmerica", "BOG": "SouthAmerica",
    "SYD": "Oceania", "MEL": "Oceania", "BNE": "Oceania", "PER": "Oceania", "AKL": "Oceania", "WLG": "Oceania",
}
REGION_ORDER = ["HONGKONG", "EastAsia", "SoutheastAsia", "NorthAmerica", "Europe", "MiddleEast", "Africa", "SouthAmerica", "Oceania"]



# ================= curl 检测（仅用于数据源抓取）=================
def _find_curl():
    extra = [r"C:\Windows\System32\curl.exe", r"C:\Program Files\curl\bin\curl.exe"] if PLATFORM == "windows" else []
    for p in ["/usr/sbin/curl", "/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"] + extra:
        if os.path.isfile(p) and os.access(p, os.X_OK): return p
    return shutil.which("curl")
CURL_BIN = _find_curl()
HAS_CURL = CURL_BIN is not None

# ================= 日志系统 =================
_log_lock  = threading.Lock()
_done_lock = threading.Lock()
_done_cnt  = [0]
_fail_cnt  = [0]
def log(level, msg):
    thread_name = threading.current_thread().name
    line = f"{time.strftime('%H:%M:%S')} [{level}] [{thread_name}] {msg}"
    with _log_lock:
        try:
            with open(str(LOG_FILE), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except: pass
    if level in ("INFO", "ERROR", "WARN", "HIT", "FINAL", "PROG"):
        print(line)
        sys.stdout.flush()

# ================= HTTP 工具（数据源抓取用）=================
def _http_get(url, timeout=15):
    if HAS_CURL:
        try:
            r = subprocess.run([CURL_BIN, "-sf", "--max-time", str(timeout), url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout+3)
            if r.returncode == 0: return r.stdout
        except: pass
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp: return resp.read()
    except Exception as e:
        log("WARN", f"_http_get failed {url}: {e}"); return None

def _http_post_file(url, payload_str, timeout=15):
    import tempfile
    import time

    max_retries = 10  # 默认最大重试次数
    last_exception = None

    for attempt in range(1, max_retries + 1):
        # 重试前等待（第一次不等待）
        if attempt > 1:
            time.sleep(1)  # 简单延迟，可根据需要调整为指数退避
            log("WARN", f"Retry attempt {attempt}/{max_retries} for {url}")

        # ---------- 尝试 curl ----------
        if HAS_CURL:
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
                    tmp.write(payload_str)
                    tmp_path = tmp.name
                # 执行 curl 命令
                result = subprocess.run(
                    [CURL_BIN, "-s", "-X", "POST", url,
                     "-H", "Content-Type: application/json",
                     "-d", f"@{tmp_path}"],
                    timeout=timeout,
                    capture_output=True,   # 捕获输出以便检查错误
                    text=True
                )
                # 检查返回码（curl 非零表示失败）
                if result.returncode == 0:
                    log("INFO", f"POST (file) OK {url} (attempt {attempt})")
                    return
                else:
                    raise Exception(f"curl exited with {result.returncode}, stderr: {result.stderr}")

            except Exception as e:
                log("WARN", f"post_file curl fail (attempt {attempt}): {e}")
                last_exception = e
                # 继续尝试 urllib fallback
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass

        # ---------- 回退：urllib ----------
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, data=payload_str.encode(),
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                resp.read()
            log("INFO", f"POST (urllib) OK {url} (attempt {attempt})")
            return
        except Exception as e:
            log("ERROR", f"POST FAIL {url} (attempt {attempt}): {e}")
            last_exception = e
            # 继续下一次重试

    # 所有重试均失败
    log("ERROR", f"All {max_retries} retries exhausted for POST {url}. Last error: {last_exception}")

# ================= 数据源获取 =================
def fetch_domains(max_retry=5):
    for attempt in range(1, max_retry + 1):
        raw = _http_get(DOMAINS_SET_URL)
        if raw:
            try:
                data = json.loads(raw.decode())
                if isinstance(data, list):
                    domains = [str(x).strip() for x in data if str(x).strip()]
                    log("INFO", f"GET domains count={len(domains)}"); return domains
            except Exception as e: log("WARN", f"parse domains fail {attempt}: {e}"); time.sleep(2*attempt)
    log("ERROR", "GET domains failed"); sys.exit(1)

def _fetch_single_url_ips(url):
    """从单个 URL 抓取 IP 列表"""
    html = _http_get(url, timeout=20)
    if not html:
        return []
    html_str = html.decode(errors="ignore")
    ips = re.findall(r'>(\d+\.\d+\.\d+\.\d+)<', html_str) or IP_RE.findall(html_str)
    log("INFO", f"[wetest] {url} got={len(ips)}")
    return ips

def fetch_wetest_ips():
    """并发从所有 IP_SET_URLS 抓取 IPv4 地址"""
    all_ips = set()
    urls = IP_SET_URLS + POST_URLS
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(urls), 30)) as executor:
        future_to_url = {executor.submit(_fetch_single_url_ips, u): u for u in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                ips = future.result()
                all_ips.update(ips)
            except Exception:
                pass
    ips = list(all_ips)
    log("INFO", f"wetest TOTAL IP count={len(ips)}")
    return ips

# ================= DNS 解析 =================
def is_ip(s):
    """判断字符串是否为合法 IPv4 地址"""
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", s))

def _resolve_via_dig(domain):
    """
    方法1：Linux/macOS/iStoreOS 使用 dig @223.6.6.6 解析域名。
    绕过 Clash fake-ip（fake-ip 段 198.18.x.x 被过滤），返回真实 CF IP 列表。
    """
    dig_bin = shutil.which("dig")
    if not dig_bin:
        return []
    try:
        r = subprocess.run(
            [dig_bin, "@223.6.6.6", "+short", "+time=2", "+tries=2", domain],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3
        )
        ips = [
            line.strip() for line in r.stdout.decode().strip().splitlines()
            if is_ip(line.strip()) and not line.strip().startswith("198.18.")
        ]
        ips = list(dict.fromkeys(ips))
        if ips:
            log("INFO", f"resolve {domain} via dig@223.6.6.6 -> {ips}")
        return ips
    except Exception as e:
        return []
    

def _resolve_via_nslookup(domain):
    """
    方法2：Windows 使用 nslookup 指定 223.6.6.6 解析域名（Windows 主力方案）。
    解析输出时跳过 server/address 段（含 223.6.6.6 的行），
    提取 "Address:" 行（兼容中文系统"地址:"），过滤 fake-ip 段。
    """
    nslookup_bin = shutil.which("nslookup")
    if not nslookup_bin:
        return []
    try:
        r = subprocess.run(
            [nslookup_bin, domain, "223.6.6.6"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3
        )
        output = r.stdout.decode(errors="ignore")
        ips = []
        in_answer = False
        for line in output.splitlines():
            line = line.strip()
            if "223.6.6.6" in line:
                in_answer = True
                continue
            if not in_answer:
                continue
            if line.lower().startswith("address") or line.startswith("地址"):
                ip = line.split(":")[-1].strip().split("#")[0].strip()
                if is_ip(ip) and not ip.startswith("198.18."):
                    ips.append(ip)
        ips = list(dict.fromkeys(ips))
        if ips:
            log("INFO", f"resolve {domain} via nslookup@223.6.6.6 -> {ips}")
        return ips
    except Exception as e:
        return []
    

def _resolve_via_alibaba_doh(domain):
    """
    方法3：通过阿里 DoH（HTTPS JSON API）解析域名，作为终极 fallback。
    使用 curl 请求 https://dns.alidns.com/resolve?name=...&type=A，解析 Answer 字段。
    """
    if not HAS_CURL:
        return []
    try:
        r = subprocess.run(
            [CURL_BIN, "-sf", "--max-time", "5",
             f"https://dns.alidns.com/resolve?name={domain}&type=A"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3
        )
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout.decode())
        ips = [
            ans.get("data", "").strip()
            for ans in data.get("Answer", [])
            if is_ip(ans.get("data", "").strip()) and not ans.get("data", "").strip().startswith("198.18.")
        ]
        ips = list(dict.fromkeys(ips))
        if ips:
            log("INFO", f"resolve {domain} via alibaba DoH(dns.alidns.com) -> {ips}")
        return ips
    except Exception as e:
        return []


def _resolve_via_tencent_doh(domain):
    """
    方法3：通过腾讯 DoH 解析域名，作为终极 fallback。
    使用 curl 请求 https://doh.pub/dns-query?name=...&type=A
    """
    if not HAS_CURL:
        return []
    try:
        r = subprocess.run(
            [CURL_BIN, "-sf", "--max-time", "5",
             "-H", "accept: application/dns-json",
             f"https://doh.pub/dns-query?name={domain}&type=A"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3
        )
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout.decode())
        ips = []
        if "Answer" in data:
            for ans in data["Answer"]:
                if ans.get("type") == 1:  # A 记录
                    ip = ans.get("data", "").strip()
                    if is_ip(ip) and not ip.startswith("198.18."):
                        ips.append(ip)
        ips = list(dict.fromkeys(ips))
        if ips:
            log("INFO", f"resolve {domain} via tencent DoH(doh.pub) -> {ips}")
        return ips
    except Exception as e:
        return []

def resolve_remote_ip(domain):
    """
    域名解析入口：依次尝试三种方法，返回第一个成功的 IP 列表。
    - Linux/macOS/iStoreOS: dig → DoH
    - Windows: nslookup → DoH
    全部失败返回 None。
    """
    ips = _resolve_via_tencent_doh(domain)
    if ips:
        return ips
    ips = _resolve_via_alibaba_doh(domain)
    if ips:
        return ips

    if PLATFORM in ("linux", "macos", "istoreos"):
        ips = _resolve_via_dig(domain)
        if ips:
            return ips
    if PLATFORM == "windows":
        ips = _resolve_via_nslookup(domain)
        if ips:
            return ips
    log("WARN", f"resolve_remote_ip: all methods failed for {domain}")
    return None


def resolve_domains_concurrent(domains, max_workers=None):
    """
    并发解析域名列表，返回去重后的所有 IPv4 地址。
    max_workers 默认使用全局 CONCURRENCY。
    """
    if max_workers is None:
        max_workers = CONCURRENCY
    all_ips = set()
    dns_resolve_failed = set()
    log("INFO", f"Starting concurrent DNS resolution for {len(domains)} domains (workers={max_workers})")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(resolve_remote_ip, d): d for d in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                ips = future.result()
                if ips:
                    all_ips.update(ips)
                else:dns_resolve_failed.add(domain);
            except Exception as e:
                log("Error", f"DNS resolution failed.")
    log("INFO", f"DNS resolution done, unique IPs count={len(all_ips)}")
    log("INFO", f"DNS resolution done, dns resolve failed :  count={len(dns_resolve_failed)} , dns_resolve_failed:{dns_resolve_failed}")
    return list(all_ips)


# ================= 🔥 核心探测函数（纯Python原生） =================
# 快速获取 colo
def fetch_colo_from_trace(ip, domain="la.pingshaisland.top", timeout=10):
    """探测 /cdn-cgi/trace 获取 colo（纯网络测量，无缓存）"""
    sock = None
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=domain)
        ssock.send(_build_request("GET", "/cdn-cgi/trace", domain, "close"))
        data = b""
        while len(data) < 4096:
            chunk = ssock.recv(1024 * 128)
            if not chunk: break
            data += chunk
            if b"\r\n\r\n" in data and b"colo=" in data: break
        for line in data.decode(errors="ignore").splitlines():
            if line.startswith("colo="):
                return line.split("=", 1)[1].strip()
        return None
    except Exception:
        return None
    finally:
        if sock:
            try: sock.close()
            except: pass

def probe_full_path(ip, domain, test_path="/test.bin", timeout=5):
    """全链路延迟测量：本地 → CF边缘 → VPS回源"""
    res = {'success': False, 'ttfb_ms': None, 'tcp_ms': None, 'tls_ms': None, 'total_ms': None, 'colo': None, 'error': None}
    t_start = time.perf_counter()
    
    # 1. TCP
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        res['tcp_ms'] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:
        res['error'] = f"TCP:{e}"
        log("WARN", f"ip={ip} TCP connect failed: {e}")
        return res

    # 2. TLS
    t0 = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        if ORIGIN_VERIFY_CERT: ctx.check_hostname = True; ctx.verify_mode = ssl.CERT_REQUIRED
        else: ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=domain)  # SNI
        res['tls_ms'] = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as e:
        sock.close()
        res['error'] = f"TLS:{e}"
        log("WARN", f"ip={ip} TLS handshake failed: {e}")
        return res
    


    # 3. 同一连接上获取 colo（轻量 trace 请求，不计入延迟测量）
    try:
        ssock.settimeout(timeout)
        ssock.sendall(_build_request("GET", "/cdn-cgi/trace", domain, "keep-alive"))
        trace_data = b""
        while len(trace_data) < 4096:
            chunk = ssock.recv(1024 * 128)
            if not chunk: break
            trace_data += chunk
            if b"\r\n\r\n" in trace_data and b"colo=" in trace_data: break
        for line in trace_data.decode(errors="ignore").splitlines():
            if line.startswith("colo="):
                res['colo'] = line.split("=", 1)[1].strip()
                break
    except Exception:
        pass  # colo 获取失败不影响后续延迟测量

    # 4. HTTP TTFB（测试文件）
    req = _build_request("GET", f"{test_path}?t={int(time.time())}", domain, "close",
                         extra_headers="Upgrade-Insecure-Requests: 1\r\n")
    try:
        ssock.settimeout(timeout)
        t0 = time.perf_counter()
        ssock.sendall(req)                      # 发送完整请求

        first_byte = ssock.recv(1)  # TTFB 关键点
        if not first_byte: raise Exception("No response")
        
        # 读取响应头
        data = first_byte
        if data :
           data+=ssock.recv(1024*128)  # 接受 128KB
        recv_time = 0
        data_length = len(data)
        while True:
            chunk = ssock.recv(1024*128)
            if not chunk: break
            data_length = data_length+len(chunk)
            recv_time=recv_time+1
            if (recv_time%50==0):
                now_speed = round((data_length/1024)/(time.perf_counter() - t0), 1)
                if now_speed<(LOWEST_SPEED/4):
                    log("INFO", f"ip={ip} recv_time ={recv_time},now_speed={now_speed}KB/S, less than {LOWEST_SPEED/4}KB/S! too slow! discard this!")
                    raise Exception("too slow!discard this!")

        
        status_line = data.split(b"\r\n")[0].decode(errors="ignore")
        res['ttfb_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        res['success'] = " 200 " in status_line or " 3" in status_line[:50]
        res['total_ms'] = round((time.perf_counter() - t_start) * 1000, 1)
        if not res['success']:
            log("WARN", f"ip={ip} non-success HTTP status: {status_line.strip()}")
    except Exception as e:
        res['error'] = f"HTTP:{e}"
        log("WARN", f"ip={ip} HTTP request failed: {e}")
    finally:
        try: ssock.unwrap()
        except: pass
        try: sock.shutdown(socket.SHUT_RDWR)
        except: pass
        sock.close()
    return res

# ================= HTTP 指纹 =================
_HTTP_FINGERPRINT = (
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
    "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Cache-Control: no-cache, no-store\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Sec-Fetch-Site: none\r\n"
    "Sec-Fetch-User: ?1\r\n"
)

def _build_request(method, path, host, connection, extra_headers=""):
    return f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: {connection}\r\n{_HTTP_FINGERPRINT}{extra_headers}\r\n".encode()

# ================= 探测调度与评分 =================
_tested_ips = set()
_tested_ips_lock = threading.Lock()
_colo_cache = {}
_colo_cache_lock = threading.Lock()

def _score(avg_lat, tcp_loss, tls_loss, http_loss):
    """  收紧阈值：TCP/TLS 任一失败即重罚，业务丢包按权重扣分"""
    if tcp_loss > 0.2: return 999999   # 3次中1次TCP不通直接淘汰

    if tls_loss > 0.2: return 999999   # 3次中1次TLS失败重罚
    return avg_lat * WEIGHT_LATENCY + http_loss * LOSS_PENALTY_MS * WEIGHT_LOSS

def _probe_single_ip(real_ip, target):
    tcp_ok = tls_ok = http_ok = 0
    latencies = []
    eachProbeInfo = []
    colo = None
    for i in range(PROBE_REPEAT):
        for ORIGIN_SNI in ORIGIN_SNI_LIST:
            latency=None
            time.sleep(SLEEP_INTERVAL)
            if PROBE_MODE == "full":
                res = probe_full_path(real_ip, ORIGIN_SNI, test_path=ORIGIN_TEST_PATH, timeout=TIMEOUT)
                if not res['success']:
                    log("WARN", f"ip={real_ip} probe_full_path failed for {ORIGIN_SNI}: {res.get('error', 'unknown')}")
                    return None
                colo = res.get('colo')
                if colo:
                    with _colo_cache_lock:
                        _colo_cache[real_ip] = colo
                if not colo:
                    log("WARN", f"ip={real_ip} failed to get colo after successful probe_full_path for {ORIGIN_SNI}")
                    return None
                http_ok += 1
                tcp_ok += 1
                tls_ok += 1
                latency = round(res['tcp_ms']+res['ttfb_ms'],1)
                latencies.append(latency)
                eachProbeInfo.append(colo+":"+str(latency)+"ms")
            else:
                t0 = time.perf_counter()
                colo = fetch_colo_from_trace(real_ip, ORIGIN_SNI)
                if not colo:
                    log("WARN", f"ip={real_ip} failed to get colo (edge mode) for {ORIGIN_SNI}")
                    return None
                latency = round((time.perf_counter() - t0) * 1000, 1)
                latencies.append(latency)
                tcp_ok += 1
                tls_ok += 1
                http_ok += 1
                eachProbeInfo.append(colo+":"+str(latency)+"ms")

    sorted_lat = sorted(latencies)
    trimmed_lat = sorted_lat[:-1] if len(sorted_lat) >= 3 else sorted_lat
    avg_lat = round(sum(trimmed_lat) / len(trimmed_lat), 1) if trimmed_lat else 9999
    tcp_loss = 1 - (tcp_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    tls_loss = 1 - (tls_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    http_loss = 1 - (http_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    score = round(_score(avg_lat, tcp_loss, tls_loss, http_loss), 1)

    if score >= 999999:
        log("WARN", f"ip={real_ip} discarded: tcp_loss={tcp_loss} tls_loss={tls_loss} (score={score})")

    log("INFO", f'avg_lat={avg_lat}ms ip={real_ip} {eachProbeInfo}')
    
    return {
        "target": target, "real_ip": real_ip, "colo": colo,
        "lat": round(avg_lat, 1), "loss": round(http_loss, 2),
        "tcp_loss": round(tcp_loss, 2), "tls_loss": round(tls_loss, 2), "http_loss": round(http_loss, 2),
        "score": round(score, 2), "mode": PROBE_MODE
    }

def probe_target_full(target):
    if is_ip(target):
        ip_list = [target]
    else:
        ip_list = resolve_remote_ip(target)
        if not ip_list:
            log("WARN", f"probe_target_full: DNS resolution failed for {target}, skipping")
            return []
    
    results = []
    for real_ip in ip_list:
        with _tested_ips_lock:
            if real_ip in _tested_ips: continue
            _tested_ips.add(real_ip)
        
        r = _probe_single_ip(real_ip, target)
        if r:
            results.append(r)
    return results

def worker(q, results, total, worker_name):
    """工作线程：从队列取任务探测，保证 task_done() 必定被调用"""
    threading.current_thread().name = worker_name   # 显式命名
    while True:
        d = None
        try:
            d = q.get()
            if d is None:
                # 哨兵：退出前仍要 task_done()
                q.task_done()
                log("INFO", f" received STOP signal, exiting")
                break

            # 执行探测
            plist = probe_target_full(d)

            with _done_lock:
                _done_cnt[0] += 1
                done = _done_cnt[0]
                if not plist:
                    _fail_cnt[0] += 1
                    log("WARN", f"target={d} produced 0 valid results, fail={_fail_cnt[0]}")
                for r in plist:
                    results.append(r)
                if done % PROG_INTERVAL == 0 or done == total:
                    log("PROG", f" progress={done}/{total} hits={len(results)} fail={_fail_cnt[0]}")
        except Exception as e:
            # 捕获一切异常，避免线程崩溃
            log("ERROR", f" worker crashed: {type(e).__name__}: {e}")
            # 即使崩溃也要标记任务完成（否则队列 join 会死锁）
        finally:
            if d is not None:
                q.task_done()   # 无论成功、失败、None 哨兵，都调用一次 task_done

def _dedup_by_best_score(results):
    best = {}
    for r in results:
        if r["real_ip"] not in best or r["score"] < best[r["real_ip"]]["score"]: best[r["real_ip"]] = r
    return list(best.values())

def select_top(results, n=TOP_N):
    d = _dedup_by_best_score(results); d.sort(key=lambda x: x["score"])
    log("INFO", f"select_top: valid={len(results)} deduped={len(d)} picked={min(n, len(d))}")
    return d[:n]

def top_region(results, region=None, colo=None, topN=5):
    if not results: raise ValueError("results不能为空")
    if not colo and not region: raise ValueError("region 和 colo 必须至少填一个")
    f = _dedup_by_best_score(results)
    if colo: f = [x for x in f if x["colo"] == colo]
    elif region: f = [x for x in f if REGION_MAP.get(x["colo"]) == region]
    f.sort(key=lambda x: x["score"])
    return f[:topN]

def print_top_results(top):
    log("FINAL", "==== FINAL TOP ====")
    for r in top:
        log("FINAL", f'{r["real_ip"]} (from {r["target"]}) -> {r["colo"]} lat={r["lat"]}ms loss={r["loss"]} score={r["score"]}')

def post_all_results(results):
    if not results: return
    nodes = [{"ip": r["real_ip"], "colo": r["colo"], "lat": r["lat"], "loss": r["loss"], "source": "" if is_ip(r["target"]) else r["target"]} for r in results]
    log("INFO", f"post_all_results: uploading {len(nodes)} nodes")
    threads = [threading.Thread(target=_http_post_file, args=(u, json.dumps(nodes, ensure_ascii=False)), daemon=False) for u in POST_URLS]
    for t in threads: t.start()
    for t in threads: t.join()

# ================= 阿里云 DNS =================
def send_to_aliyunDNS(ip_list, domain, max_retry=ALI_DNS_MAX_RETRY):
    """
    通过阿里云 DNS SDK 将 ip_list 同步为 domain 的 A 记录。
    流程：查询现有记录 → 比对变化（无变化跳过）→ 删除旧记录 → 新增新记录。
    失败时指数退避重试，遇不可重试错误（InvalidProduct.NotFound）立即终止。
    """
    if not ip_list:
        log("WARN", "AliDNS: empty ip_list")
        return
    try:
        from alibabacloud_alidns20150109.client import Client as DnsClient
        from alibabacloud_tea_openapi import models as open_api_models
        from alibabacloud_alidns20150109 import models as dns_models
    except:
        log("ERROR", "Aliyun SDK not installed")
        return
    config = open_api_models.Config(access_key_id=ALI_ACCESS_KEY_ID,access_key_secret=ALI_ACCESS_KEY_SECRET,)
    config.endpoint = ALI_DNS_ENDPOINT
    client = DnsClient(config)
    parts = domain.split(".")
    rr   = parts[0]
    root = ".".join(parts[1:])
    for attempt in range(1, max_retry + 1):
        try:
            log("INFO", f"AliDNS attempt {attempt}/{max_retry}")
            req  = dns_models.DescribeDomainRecordsRequest(domain_name=root, type="A")
            resp = client.describe_domain_records(req)
            records        = resp.body.domain_records.record or []
            target_records = [r for r in records if r.rr == rr]
            old_ips        = [r.value for r in target_records]
            if set(old_ips) == set(ip_list):
                log("INFO", "AliDNS skip (no change)")
                return
            for r in target_records:
                client.delete_domain_record(dns_models.DeleteDomainRecordRequest(record_id=r.record_id))
                log("INFO", f"AliDNS DELETE {domain} -> {r.value}")
            for ip in ip_list:
                client.add_domain_record(dns_models.AddDomainRecordRequest(domain_name=root,rr=rr,type="A",value=ip,ttl=ALI_DNS_TTL))
                log("INFO", f"AliDNS ADD {domain} -> {ip}")
            log("INFO", "AliDNS SUCCESS")
            return
        except Exception as e:
            err = str(e)
            log("ERROR", f"AliDNS attempt {attempt} failed: {err}")
            if "InvalidProduct.NotFound" in err:
                log("ERROR", "AliDNS fatal error, stop retry")
                return
            if attempt == max_retry:
                log("ERROR", "AliDNS reached max retry, abort")
                return
            sleep_sec = min(2 ** attempt, 10)
            log("WARN", f"AliDNS retry in {sleep_sec}s...")
            time.sleep(sleep_sec)

def test_download_speed(test_list,lowest_speed=850,count=20):
    """测试速度"""
    if not test_list :
        log("WARN", "No IPs to test_download_speed, skip")
        return
    list_to_test_speed = select_top(test_list,5*count)
    pass_cnt=0

    for each in list_to_test_speed :
        test_download_speed_res = probe_full_path(each['real_ip'], ORIGIN_SNI_LIST[0], test_path=ORIGIN_SPEED_TEST_PATH, timeout=100)
        if not test_download_speed_res['success']:continue
        cost_time_ms = round(test_download_speed_res['tcp_ms']+test_download_speed_res['ttfb_ms'],1)
        download_speed = round((10*1024)/(cost_time_ms/1000),1)
        each['download_speed'] = round(download_speed,1)
        each['download_cost_time'] = cost_time_ms
        each['score'] = round(each['score'] - download_speed,1)
        each['lat'] = round(each['lat'] - download_speed,1)
        log("INFO", f"colo={each['colo']}  ip={each['real_ip']}  download_speed={each['download_speed']}KB/S cost_time_ms={each['download_cost_time']} score={each['score']}")
        if download_speed>lowest_speed:pass_cnt=pass_cnt+1
        if pass_cnt>=count:return



def _run_probe_phases(ip_list, results):
    """只探测 IP 列表，每个 IP 作为一个独立任务"""
    total = len(ip_list)
    if total == 0:
        log("WARN", "No IPs to probe, skip")
        return
    q = queue.Queue()
    workers = min(CONCURRENCY, total)
    ts = []
    for i in range(workers):
        name = f"Worker-{i+1}"
        t = threading.Thread(
            target=worker,
            args=(q, results, total, name),
            name=name,
            daemon=True
        )
        t.start()
        ts.append(t)

    log("INFO", f"==== Probing {total} IPs (workers={workers}) ====")
    for ip in ip_list:
        q.put(ip)
    q.join()
    log("INFO", "==== Probing DONE ====")

    # 发送停止信号
    for _ in ts:
        q.put(None)
    for t in ts:
        t.join()

def main():
    # 启动前校验 full 模式配置
    if not ORIGIN_SNI_LIST or not ORIGIN_TEST_PATH:
        log("ERROR", "ORIGIN_SNI_LIST 和 ORIGIN_TEST_PATH 不能为空！请检查脚本顶部配置。")
        sys.exit(1)
    log("INFO", f"mode={PROBE_MODE} SNI={ORIGIN_SNI_LIST} path={ORIGIN_TEST_PATH} verify={ORIGIN_VERIFY_CERT}")


    #test_download_speed([{"real_ip":"172.64.146.211","ip": "172.64.146.211", "colo": "HKG", "lat": 102.4, "loss": 0.0, "source": "","score":9999999},])

    # 1. 并发获取域名列表和原始 IP 列表
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_domains = executor.submit(fetch_domains)
        future_ips = executor.submit(fetch_wetest_ips)
        domains = list(dict.fromkeys(future_domains.result()))
        raw_ips = list(dict.fromkeys(future_ips.result()))
    log("INFO", f"Total domains={len(domains)}, raw_ips={len(raw_ips)}")

    # 2. 并发解析所有域名 → 得到域名解析出的 IP 列表
    domain_ips = resolve_domains_concurrent(domains, max_workers=40)

    # 3. 合并去重：域名解析 IP + 原始 IP 列表
    all_ips = list(set(domain_ips+raw_ips))
    log("INFO", f"Final IPs to probe: {len(all_ips)}")

    # 4. 并发探测所有 IP
    results = []
    _run_probe_phases(all_ips,results)
    test_download_speed_res = top_region(results, colo="HKG", topN=80)+top_region(results, region="NorthAmerica", topN=80)+top_region(results, region="EastAsia", topN=80) 
    test_download_speed(test_download_speed_res,LOWEST_SPEED,30)
    log("INFO", f"Total IPs probed={len(all_ips)} valid={len(results)} fail={_fail_cnt[0]}")
    post_all_results(select_top(results,1000))
    top_n_res = top_region(results, colo="HKG", topN=8)+top_region(results, region="NorthAmerica", topN=8)+top_region(results, region="EastAsia", topN=8) 
    top_n_res = select_top(top_n_res,10)
    print_top_results(top_n_res)
    
    #更改aliyun DNS
    if CHANGE_DNS_RESOLVE:
        for cfg in ALI_DNS_TARGETS:
            send_to_aliyunDNS([r["real_ip"] for r in top_n_res], cfg["domain"])

if __name__ == "__main__":
    main()