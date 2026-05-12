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
import ipaddress
# ================= 配置导入 =================
from config import *
# ================= 路径与文件 =================
BASE_DIR = Path(__file__).resolve().parent
def get_today():
    """返回当前日期字符串，格式 YYYYMMDD，用于日志/CSV 文件名"""
    return datetime.now().strftime("%Y%m%d")
LOG_FILE = BASE_DIR / f"{get_today()}_cf_test.log"
HIT_FILE = BASE_DIR / f"{get_today()}_cf_hits.csv"



# ================= 平台检测 =================
def detect_platform():
    """检测当前运行平台：istoreos / windows / macos / linux"""
    if Path("/etc/openwrt_release").exists(): return "istoreos"
    s = sys.platform
    if s == "win32": return "windows"
    if s == "darwin": return "macos"
    return "linux"
PLATFORM = detect_platform()
CONCURRENCY = {"istoreos": 8, "windows": 20, "macos": 10, "linux": 10}.get(PLATFORM, 20)

# ================= 正则 =================
IP_RE = re.compile(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')

# ================= colo 映射 =================
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
    """查找系统中可用的 curl 可执行文件路径，找不到返回 None"""
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

# ================= 增量测速状态 =================
_early_stop_flag = [False]  # 提前终止标志（线程安全列表）
_speed_pass_count = [0]     # 速度达标累计数
_batch_lock = threading.Lock()  # 批次测速锁
def log(level, msg):
    """线程安全的日志输出：写入日志文件，INFO/ERROR/WARN/HIT/FINAL/PROG 级别同步打印到终端"""
    thread_name = threading.current_thread().name
    line = f"{time.strftime('%H:%M:%S')} [{level}] [{thread_name}] {msg}"
    with _log_lock:
        try:
            with open(str(LOG_FILE), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError: pass
    if level in ("INFO", "ERROR", "WARN", "HIT", "FINAL", "PROG"):
        print(line)
        sys.stdout.flush()

# ================= HTTP 工具（数据源抓取用）=================
def _http_get(url, timeout=15):
    """HTTP GET 请求：优先 curl，失败回退 urllib；返回响应字节或 None"""
    if HAS_CURL:
        try:
            r = subprocess.run([CURL_BIN, "-sf", "--max-time", str(timeout), url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout+3)
            if r.returncode == 0: return r.stdout
        except Exception: pass
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp: return resp.read()
    except Exception as e:
        log("WARN", f"_http_get failed {url}: {e}"); return None

def _http_post_file(url, payload_str, timeout=15):
    """HTTP POST 上传 JSON 字符串：优先 curl 临时文件方式，失败回退 urllib；最多重试 10 次"""
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
                    except OSError:
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
    """从 DOMAINS_SET_URL 拉取域名列表，失败重试 max_retry 次，全部失败则退出进程"""
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

# ================= Cloudflare CIDR 过滤 =================
_cf_ipv4_cidrs = None
_cf_cidr_lock = threading.Lock()

def fetch_cloudflare_cidrs():
    """
    获取 Cloudflare IPv4 CIDR 列表。
    1. 内存缓存（已加载则直接返回）
    2. API 请求
    3. 失败则使用 config.CF_DEFAULT_IPV4_CIDRS
    返回 ipaddress.IPv4Network 对象列表。
    """
    global _cf_ipv4_cidrs
    with _cf_cidr_lock:
        if _cf_ipv4_cidrs is not None:
            return _cf_ipv4_cidrs

    # 尝试调用官方 API，最多 3 次重试
    for attempt in range(1, 4):
        try:
            raw = _http_get("https://api.cloudflare.com/client/v4/ips", timeout=15)
            if not raw:
                raise ValueError("Empty response")
            data = json.loads(raw.decode())
            if not data.get("success"):
                raise ValueError(f"API error: {data.get('errors', [{}])[0].get('message', 'unknown')}")
            cidr_list = data.get("result", {}).get("ipv4_cidrs", [])
            if not cidr_list:
                raise ValueError("No ipv4_cidrs in response")
            _cf_ipv4_cidrs = [ipaddress.IPv4Network(cidr) for cidr in cidr_list]
            log("INFO", f"Fetched {_cf_ipv4_cidrs.__len__()} Cloudflare IPv4 CIDR ranges from API")
            return _cf_ipv4_cidrs
        except Exception as e:
            log("WARN", f"Fetch CF CIDRs attempt {attempt}/3 failed: {e}")
            if attempt < 3:
                time.sleep(2 ** attempt)

    # API 全部失败，使用 config 中的默认 CIDR 配置
    try:
        default_cidrs = CF_DEFAULT_IPV4_CIDRS
    except NameError:
        default_cidrs = []

    if default_cidrs:
        try:
            _cf_ipv4_cidrs = [ipaddress.IPv4Network(c) for c in default_cidrs]
            log("WARN", f"Using {len(_cf_ipv4_cidrs)} default CF CIDRs from config (API failures)")
            return _cf_ipv4_cidrs
        except Exception as e:
            log("ERROR", f"Parse default CF CIDRs failed: {e}")

    log("WARN", "Using empty CF CIDR list - all IPs will pass filter")
    return []

def is_cf_ip(ip_str):
    """
    判断单个 IPv4 地址是否属于 Cloudflare 网段。
    使用标准库 ipaddress 模块进行 CIDR 匹配。
    如果 CF CIDRs 未加载（缓存为空），返回 True（容错模式）。
    """
    global _cf_ipv4_cidrs
    if not _cf_ipv4_cidrs:
        return True  # 无规则即不过滤
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in cidr for cidr in _cf_ipv4_cidrs)
    except ValueError:
        return False  # 非法 IP 地址直接拒绝

def filter_cf_ips(ips_list):
    """
    并发过滤 IP 列表，只保留 Cloudflare 网段的 IP。
    使用线程池并行执行 is_cf_ip() 检查，线程数 = CPU 核数 * 2。
    返回过滤后的 IP 列表。
    """
    if not ips_list:
        return []

    # 确保先加载 CIDR 规则（但不会阻塞太久）
    fetch_cloudflare_cidrs()

    max_workers = max(4, os.cpu_count() * 2)
    filtered = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(is_cf_ip, ip): ip for ip in ips_list}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    filtered.append(ip)
            except Exception:
                pass  # 忽略单个 IP 的异常，不影响其他 IP

    log("INFO", f"CF filter: {len(ips_list)} raw -> {len(filtered)} valid CF IPs")
    return filtered

# ================= DNS 解析 =================
def _fetch_have_post_res(url):
    """从单个 HAVE_POST_RES URL 获取历史优结果，返回 (ip, source_url, speed_kb_s) 列表"""
    try:
        raw = _http_get(url, timeout=5)
        if not raw:
            return []
        data = json.loads(raw.decode())
        if not isinstance(data, list):
            return []
        results = []
        for item in data:
            ip = item.get("ip")
            speed = item.get("speed_kb_s", 0)
            if ip:
                results.append((ip, url, speed))
        log("INFO", f"[HAVE_POST_RES] {url} got={len(results)} items")
        return results
    except Exception as e:
        log("WARN", f"_fetch_have_post_res failed {url}: {e}")
        return []

def fetch_have_post_res():
    """
    从 HAVE_POST_RES 获取历史优结果。
    返回格式：[(ip, source_url, speed_kb_s), ...]
    按 speed_kb_s 降序排列（速度快的在前）。
    """
    if not HAVE_POST_RES:
        log("INFO", "HAVE_POST_RES is empty, skip")
        return []

    urls = list(set(HAVE_POST_RES+POST_URLS))  # 去重
    all_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(urls), 20)) as executor:
        future_to_url = {executor.submit(_fetch_have_post_res, u): u for u in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                results = future.result()
                all_results.extend(results)
            except Exception:
                pass

    # 按 IP 去重，同一 IP 保留 speed_kb_s 最高的记录
    ip_best = {}
    for ip, url, speed in all_results:
        if ip not in ip_best or speed > ip_best[ip][1]:
            ip_best[ip] = (url, speed)

    # 转换为列表并按 speed_kb_s 降序排序（没有 speed_kb_s 的排后面）
    result_list = [(ip, url, speed) for ip, (url, speed) in ip_best.items()]
    result_list.sort(key=lambda x: x[2] if x[2] > 0 else float('-inf'), reverse=True)

    log("INFO", f"HAVE_POST_RES: raw={len(all_results)}, deduped={len(result_list)} items (sorted by speed_kb_s DESC)")
    return result_list

def fetch_wetest_ips():
    """并发从所有 IP_SET_URLS 抓取 IPv4 地址，过滤非 Cloudflare 网段，返回 [(ip, source_url), ...]"""
    ip_source = {}  # ip -> source_url
    urls = IP_SET_URLS
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(urls), 30)) as executor:
        future_to_url = {executor.submit(_fetch_single_url_ips, u): u for u in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                ips = future.result()
                for ip in ips:
                    if ip not in ip_source:
                        ip_source[ip] = url  # 记录首次出现的来源 URL
            except Exception:
                pass

    raw_ips = list(ip_source.keys())
    filtered_ips = filter_cf_ips(raw_ips)

    # 只保留过滤后的 IP，转换为 (ip, source_url) 列表
    result = [(ip, ip_source[ip]) for ip in filtered_ips]

    log("INFO", f"wetest TOTAL raw={len(raw_ips)}, cf_filtered={len(result)}")
    return result

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
    

def _resolve_via_doh(domain, url, name="DoH"):
    """通过 DoH（HTTPS JSON API）解析域名，返回 IPv4 列表（过滤 fake-ip 段）。"""
    if not HAS_CURL:
        return []
    try:
        r = subprocess.run(
            [CURL_BIN, "-sf", "--max-time", "5", "-H", "accept: application/dns-json", url],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3
        )
        if r.returncode != 0:
            return []
        data = json.loads(r.stdout.decode())
        ips = []
        for ans in data.get("Answer", []):
            if ans.get("type") == 1:  # A 记录
                ip = ans.get("data", "").strip()
                if is_ip(ip) and not ip.startswith("198.18."):
                    ips.append(ip)
        ips = list(dict.fromkeys(ips))
        if ips:
            log("INFO", f"resolve {domain} via {name} -> {ips}")
        return ips
    except Exception:
        return []

def resolve_remote_ip(domain):
    """
    域名解析入口：依次尝试三种方法，返回第一个成功的 IP 列表。
    - Tencent DoH → Alibaba DoH → dig (Linux/macOS) / nslookup (Windows)
    全部失败返回 None。
    """
    ips = _resolve_via_doh(domain, f"https://doh.pub/dns-query?name={domain}&type=A", name="tencent DoH(doh.pub)")
    if ips:
        return ips
    ips = _resolve_via_doh(domain, f"https://dns.alidns.com/resolve?name={domain}&type=A", name="alibaba DoH(dns.alidns.com)")
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
    并发解析域名列表，返回所有 IPv4 地址的 (ip, source_domain) 列表（仅 Cloudflare 网段）。
    max_workers 默认使用全局 CONCURRENCY。
    source 字段使用解析该 IP 的原始域名，而非 DOMAINS_SET_URL。
    """
    if max_workers is None:
        max_workers = CONCURRENCY
    all_ips = set()
    ip_to_domain = {}
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
                    for ip in ips:
                        if ip not in ip_to_domain:
                            ip_to_domain[ip] = domain
                else: dns_resolve_failed.add(domain)
            except Exception as e:
                log("Error", f"DNS resolution failed.")
    raw_ip_list = list(all_ips)
    # 并发过滤 DNS 解析结果，只保留 Cloudflare 官方 IP
    filtered_ips = filter_cf_ips(raw_ip_list)
    log("INFO", f"DNS resolution done, unique IPs: raw={len(raw_ip_list)}, cf_filtered={len(filtered_ips)}")
    log("INFO", f"DNS resolution done, dns resolve failed :  count={len(dns_resolve_failed)} , dns_resolve_failed:{dns_resolve_failed}")
    # Optimization 1: source 字段使用解析该 IP 的原始域名
    return [(ip, ip_to_domain[ip]) for ip in filtered_ips]


# ================= 🔥 核心探测函数（纯Python原生） =================
def _create_tls_socket(ip, domain, timeout, verify_cert=False):
    """创建 TLS 连接到 IP:443，返回 (raw_socket, ssl_socket)"""
    sock = socket.create_connection((ip, 443), timeout=timeout)
    ctx = ssl.create_default_context()
    if verify_cert:
        ctx.check_hostname = True; ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return sock, ctx.wrap_socket(sock, server_hostname=domain)

def _recv_until(ssock, stop_markers, max_size=4096):
    """从 SSL 套接字读取直到所有标记在数据中出现或达到 max_size"""
    data = b""
    while len(data) < max_size:
        chunk = ssock.recv(1024 * 128)
        if not chunk: break
        data += chunk
        if all(m in data for m in stop_markers): break
    return data

def _parse_colo(data):
    """从 /cdn-cgi/trace 响应字节中解析 colo 值，未找到返回 None"""
    for line in data.decode(errors="ignore").splitlines():
        if line.startswith("colo="):
            return line.split("=", 1)[1].strip()
    return None

def fetch_colo_from_trace(ip, domain="la.pingshaisland.top", timeout=10):
    """探测 /cdn-cgi/trace 获取 colo（纯网络测量，无缓存）"""
    sock = None
    try:
        sock, ssock = _create_tls_socket(ip, domain, timeout)
        ssock.send(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
        data = _recv_until(ssock, [b"\r\n\r\n", b"colo="], max_size=4096)
        return _parse_colo(data)
    except Exception:
        return None
    finally:
        if sock:
            try: sock.close()
            except OSError: pass

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
    


    # 3. 获取 colo：优先缓存，未命中时才发 /cdn-cgi/trace（不计入延迟测量）
    with _colo_cache_lock:
        cached_colo = _colo_cache.get(ip)
    if cached_colo and cached_colo != "UNKNOWN":
        res['colo'] = cached_colo
    else:
        try:
            ssock.settimeout(3)
            ssock.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {domain}\r\nConnection: keep-alive\r\n\r\n".encode())
            trace_data = _recv_until(ssock, [b"\r\n\r\n", b"colo="], max_size=4096)
            colo = _parse_colo(trace_data)
            if colo:
                res['colo'] = colo
            else:
                preview = trace_data[:500].decode(errors="ignore").replace("\r\n", "\\n")
                log("WARN", f"ip={ip} colo missing in response, body preview: {preview}")
        except socket.timeout:
            log("WARN", f"ip={ip} colo recv timeout")
        except Exception as e:
            log("WARN", f"ip={ip} colo recv failed: {e}")

    # 4. HTTP TTFB（测试文件）
    req = _build_request("GET", f"{test_path}?t={int(time.time())}", domain, "close",
                         extra_headers="Upgrade-Insecure-Requests: 1\r\n")
    try:
        ssock.settimeout(timeout)
        t0 = time.perf_counter()
        ssock.sendall(req)                      # 发送完整请求

        first_byte = ssock.recv(1)  # TTFB 关键点
        if not first_byte: raise Exception("No response")
        t_speed_test_0 = time.perf_counter()
        data = first_byte + ssock.recv(1024 * 128)
        data_length = len(data)
        test_when_3S= True
        test_when_10S= True
        while True:
            chunk = ssock.recv(1024*32)
            if not chunk: break
            data_length = data_length+len(chunk)
            # 5S 强制结束条件
            if (time.perf_counter() - t_speed_test_0)>=3 and  test_when_3S :
                test_when_3S = False
                now_speed = round((data_length / 1024) / (time.perf_counter() - t_speed_test_0), 1)
                if now_speed < (LOWEST_SPEED*0.2):
                    log("INFO", f"ip={ip} costTime={(time.perf_counter() - t_speed_test_0)}, speed={now_speed}KB/s < {LOWEST_SPEED*0.2}KB/s — discard!")
                    raise Exception(f"{ip} too slow")
            # 10S 强制结束条件
            if (time.perf_counter() - t_speed_test_0)>=10 and  test_when_10S :
                test_when_10S = False
                now_speed = round((data_length / 1024) / (time.perf_counter() - t_speed_test_0), 1)
                if now_speed < (LOWEST_SPEED*0.5):
                    log("INFO", f"ip={ip} costTime={(time.perf_counter() - t_speed_test_0)}, speed={now_speed}KB/s < {LOWEST_SPEED*0.5}KB/s — discard!")
                    raise Exception(f"{ip} too slow")
            # 20S 强制结束
            if (time.perf_counter() - t_speed_test_0)>=20:
                now_speed = round((data_length / 1024) / (time.perf_counter() - t_speed_test_0), 1)
                log("INFO", f"ip={ip} costTime={(time.perf_counter() - t_speed_test_0)}, speed={now_speed}KB/s !")
                break

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
        except (OSError, AttributeError): pass
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        sock.close()
    return res

# ================= HTTP 指纹 =================
_HTTP_FINGERPRINT = (
    "User-Agent:Chrome/128.0.0.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
    "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
)

def _build_request(method, path, host, connection, extra_headers=""):
    """构造 HTTP/1.1 请求字节串，拼接 Chrome 128 指纹头"""
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

def _probe_single_ip(real_ip, target, source_url=None):
    """对单个 IP 重复探测 PROBE_REPEAT 次，遍历所有 ORIGIN_SNI，返回评分结果字典；失败返回 None"""
    tcp_ok = tls_ok = http_ok = 0
    latencies = []
    each_probe_info = []
    colo = None
    # 保存最后一次成功探测的分层耗时（用于上传）
    last_tcp_ms = last_tls_ms = last_ttfb_ms = last_total_ms = 0

    for i in range(PROBE_REPEAT):
        for sni in ORIGIN_SNI_LIST:
            latency=None
            time.sleep(SLEEP_INTERVAL)
            if PROBE_MODE == "full":
                res = probe_full_path(real_ip, sni, test_path=ORIGIN_TEST_PATH, timeout=TIMEOUT)
                if not res['success']:
                    log("WARN", f"ip={real_ip} probe_full_path failed for {sni}: {res.get('error', 'unknown')}")
                    continue
                colo = res.get('colo')
                if colo:
                    with _colo_cache_lock:
                        _colo_cache[real_ip] = colo
                if not colo:
                    log("WARN", f"ip={real_ip} colo is UNKNOWN after probe_full_path for {sni}")
                    colo = "UNKNOWN"
                http_ok += 1
                tcp_ok += 1
                tls_ok += 1
                latency = round(res['tcp_ms']+res['ttfb_ms'],1)
                latencies.append(latency)
                each_probe_info.append(colo+":"+str(latency)+"ms")
                last_tcp_ms = res.get('tcp_ms', 0)
                last_tls_ms = res.get('tls_ms', 0)
                last_ttfb_ms = res.get('ttfb_ms', 0)
                last_total_ms = res.get('total_ms', 0)
            else:
                t0 = time.perf_counter()
                colo = fetch_colo_from_trace(real_ip, sni)
                if not colo:
                    log("WARN", f"ip={real_ip} failed to get colo (edge mode) for {sni}")
                    continue
                latency = round((time.perf_counter() - t0) * 1000, 1)
                latencies.append(latency)
                tcp_ok += 1
                tls_ok += 1
                http_ok += 1
                each_probe_info.append(colo+":"+str(latency)+"ms")

    sorted_lat = sorted(latencies)
    trimmed_lat = sorted_lat[:-1] if len(sorted_lat) >= 3 else sorted_lat
    avg_lat = round(sum(trimmed_lat) / len(trimmed_lat), 1) if trimmed_lat else 9999
    tcp_loss = 1 - (tcp_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    tls_loss = 1 - (tls_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    http_loss = 1 - (http_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    score = round(_score(avg_lat, tcp_loss, tls_loss, http_loss), 1)

    if score >= 999999:
        log("WARN", f"ip={real_ip} discarded: tcp_loss={tcp_loss} tls_loss={tls_loss} (score={score})")

    log("INFO", f'avg_lat={avg_lat}ms ip={real_ip} {each_probe_info}')

    return {
        "target": target, "real_ip": real_ip, "colo": colo,
        "lat": round(avg_lat, 1), "loss": round(http_loss, 2),
        "tcp_loss": round(tcp_loss, 2), "tls_loss": round(tls_loss, 2), "http_loss": round(http_loss, 2),
        "score": round(score, 2), "mode": PROBE_MODE,
        "tcp_ms": last_tcp_ms, "tls_ms": last_tls_ms, "ttfb_ms": last_ttfb_ms, "total_ms": last_total_ms,
        "source_url": source_url or ""
    }

def probe_target_full(target, source_url=None):
    """对单个目标（域名或 IP）进行全量探测：域名先 DNS 解析再逐个 IP 探测，返回结果列表"""
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

        r = _probe_single_ip(real_ip, target, source_url)
        if r:
            results.append(r)
    return results

def worker(q, results, total, worker_name, allow_early_stop=True):
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

            # 检查是否已提前终止（仅当 allow_early_stop=True 时检查）
            if allow_early_stop and _early_stop_flag[0]:
                q.task_done()
                continue

            # 任务可能是 (ip, source_url) 元组或单个 target
            if isinstance(d, tuple) and len(d) == 2:
                target, source_url = d
            else:
                target, source_url = d, None

            # 执行探测
            plist = probe_target_full(target, source_url)

            with _done_lock:
                _done_cnt[0] += 1
                done = _done_cnt[0]
                if not plist:
                    _fail_cnt[0] += 1
                    log("WARN", f"target={target} produced 0 valid results, fail={_fail_cnt[0]}")
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
    """按 real_ip 去重，同一 IP 多条记录时保留 score 最低的"""
    best = {}
    for r in results:
        ip = r["real_ip"]
        if ip not in best or r["score"] < best[ip]["score"]:
            best[ip] = r
    return list(best.values())

def select_top(results, n=TOP_N):
    """去重后按 score 升序排列，返回前 n 条最优结果"""
    d = _dedup_by_best_score(results); d.sort(key=lambda x: x["score"])
    log("INFO", f"select_top: valid={len(results)} deduped={len(d)} picked={min(n, len(d))}")
    return d[:n]

def top_region(results, region=None, colo=None, topN=5):
    """按区域或 colo 筛选，返回去重后 score 最低的前 topN 条结果"""
    if not results: raise ValueError("results不能为空")
    if not colo and not region: raise ValueError("region 和 colo 必须至少填一个")
    f = _dedup_by_best_score(results)
    if colo: f = [x for x in f if x["colo"] == colo]
    elif region: f = [x for x in f if REGION_MAP.get(x["colo"]) == region]
    f.sort(key=lambda x: x["score"])
    return f[:topN]

def print_top_results(top):
    """打印最终优选结果到日志和终端"""
    log("FINAL", "==== FINAL TOP ====")
    for r in top:
        log("FINAL", f'{r["real_ip"]} (from {r["target"]}) -> {r["colo"]} lat={r["lat"]}ms loss={r["loss"]} score={r["score"]}')

def post_all_results(results):
    """将探测结果转为 JSON 并并发 POST 到所有上报地址（含来源 URL、分层耗时、速度等完整字段）"""
    if not results: return
    nodes = []
    for r in sorted(results, key=lambda x: x.get("score", 999999)):
        nodes.append({
            "ip": r["real_ip"],
            "colo": r.get("colo", ""),
            "score": r.get("score", 999999),
            "lat": r.get("lat", 0),
            "loss": r.get("loss", 0),
            "source": r.get("source_url", ""),
            "speed_kb_s": r.get("download_speed", 0),
            "tcp_ms": r.get("tcp_ms", 0),
            "tls_ms": r.get("tls_ms", 0),
            "ttfb_ms": r.get("ttfb_ms", 0),
            "total_ms": r.get("total_ms", 0)
        })
    log("INFO", f"post_all_results: uploading {len(nodes)} nodes")
    threads = [threading.Thread(target=_http_post_file, args=(u, json.dumps(nodes, ensure_ascii=False, indent=4, sort_keys=True)), daemon=False) for u in POST_URLS]
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
    except ImportError:
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

def incremental_batch_speed_test(results, batch_size=100, target_pass_total=20, allow_early_stop=True):
    """
    增量批次测速：每完成 batch_size 个 IP 延迟测试后，从已完成的结果中选取三区域各 Top5 进行测速。
    当全局速度达标数达到 target_pass_total 时设置提前终止标志（仅 allow_early_stop=True 时）。
    返回本轮新增的达标数量。
    """
    # _speed_pass_count 和 _early_stop_flag 是列表类型，修改元素不需要 global 声明

    if allow_early_stop and _early_stop_flag[0]:
        return 0

    with _batch_lock:
        # 从当前结果中选取三区域各 Top5
        try:
            na_top = top_region(results, region="NorthAmerica", topN=8)
            hk_top = top_region(results, colo="HKG", topN=5)
            ea_top = top_region(results, region="EastAsia", topN=2)
        except ValueError:
            return 0  # 结果不足

        # 合并去重（避免同一 IP 出现在多个区域被重复测速）
        tested_ips = set()
        batch_to_test = []
        for r in na_top + hk_top + ea_top:
            if r['real_ip'] not in tested_ips:
                tested_ips.add(r['real_ip'])
                batch_to_test.append(r)

        if not batch_to_test:
            return 0

        log("INFO", f"=== Incremental batch speed test: {len(batch_to_test)} IPs ===")

        # 对这批 IP 进行测速
        local_pass = 0
        for each in batch_to_test:
            if _early_stop_flag[0]:
                break

            res = probe_full_path(each['real_ip'], ORIGIN_SNI_LIST[0], test_path=ORIGIN_SPEED_TEST_PATH, timeout=100)
            if not res['success']:
                continue

            cost_time_ms = round(res['tcp_ms'] + res['ttfb_ms'], 1)
            download_speed = round((10 * 1024) / (cost_time_ms / 1000), 1)

            each['download_speed'] = round(download_speed, 1)
            each['download_cost_time'] = cost_time_ms

            log("INFO", f"BATCH colo={each['colo']} ip={each['real_ip']} download_speed={each['download_speed']}KB/S lat={each['lat']}ms")

            if download_speed > LOWEST_SPEED:
                local_pass += 1
                _speed_pass_count[0] += 1
                log("INFO", f"BATCH speed PASS: {_speed_pass_count[0]}/{target_pass_total}")

        # 检查是否已达到总目标（仅 allow_early_stop=True 时设置早停标志）
        if allow_early_stop and _speed_pass_count[0] >= target_pass_total:
            _early_stop_flag[0] = True
            log("INFO", f"=== Early stop triggered: {_speed_pass_count[0]} IPs passed speed test ===")

        return local_pass


def _full_batch_speed_test(results):
    """
    全量速度复测：遍历 results 中所有 run probe_full_path 里的未测速的 IP，
    逐个跑 ORIGIN_SPEED_TEST_PATH 速度测试。
    与 incremental_batch_speed_test 的区别：
    - 不抽样：全量遍历，不按区域选 Top
    - 不限制区域：所有 IP 都测
    - 不设置早停标志：纯测速
    """
    untested = [r for r in results if r.get('download_speed', 0) == 0]
    if not untested:
        log("INFO", "_full_batch_speed_test: all IPs already speed-tested, skip")
        return 0

    log("INFO", f"=== Full batch speed test: {len(untested)} IPs ===")
    tested_count = 0

    for each in untested:
        res = probe_full_path(each['real_ip'], ORIGIN_SNI_LIST[0],
                              test_path=ORIGIN_SPEED_TEST_PATH, timeout=100)
        if not res['success']:
            log("WARN", f"FULL SPEED {each['real_ip']} probe failed, skip")
            continue

        cost_time_ms = round(res['tcp_ms'] + res['ttfb_ms'], 1)
        download_speed = round((10 * 1024) / (cost_time_ms / 1000), 1)

        each['download_speed'] = round(download_speed, 1)
        each['download_cost_time'] = cost_time_ms
        tested_count += 1

        log("INFO", f"FULL SPEED colo={each['colo']} ip={each['real_ip']} "
                     f"download_speed={each['download_speed']}KB/S lat={each['lat']}ms")

    passed = sum(1 for r in untested if r.get('download_speed', 0) >= LOWEST_SPEED)
    log("INFO", f"_full_batch_speed_test done: {tested_count} tested, {passed} passed (>= {LOWEST_SPEED}KB/s)")
    return tested_count


def _rank_by_speed(results):
    """
    最终速度排名：对已完成测速的 IP，按 download_speed 降序排名赋分。
    - 测速达标 (>= LOWEST_SPEED)：score = 排名序号（1, 2, 3...）
    - 测速不达标 (< LOWEST_SPEED)：score = 9999 垫底
    - 未测速：保持原有的延迟+丢包 score 不变
    """
    speed_tested = [r for r in results if r.get('download_speed', 0) > 0]
    if not speed_tested:
        return

    # 按 download_speed 降序排序
    speed_tested.sort(key=lambda x: x['download_speed'], reverse=True)

    for rank, r in enumerate(speed_tested, start=1):
        if r['download_speed'] >= LOWEST_SPEED:
            r['score'] = rank
        else:
            r['score'] = 9999

    passed = sum(1 for r in speed_tested if r['score'] != 9999)
    log("INFO", f"_rank_by_speed: {len(speed_tested)} tested, {passed} passed (>= {LOWEST_SPEED}KB/s), scored by speed rank")


def _run_probe_phases(ip_source_list, results, allow_early_stop=True):
    """
    只探测 IP 列表，每个 (ip, source_url) 作为一个独立任务。
    每完成 100 个 IP 的延迟测试后，触发一次增量批次测速。
    如果早停标志被设置（且 allow_early_stop=True），则不再投递剩余任务并提前结束。
    """
    total = len(ip_source_list)
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
            args=(q, results, total, name, allow_early_stop),
            name=name,
            daemon=True
        )
        t.start()
        ts.append(t)

    log("INFO", f"==== Probing {total} IPs (workers={workers}) ====")

    # 分批投递，每 100 个检查一次是否早停
    batch_size = 100
    idx = 0
    last_batch_done = 0  # 上批次完成时的 _done_cnt 值

    while idx < total:
        if allow_early_stop and _early_stop_flag[0]:
            log("INFO", "Early stop detected, stopping probe...")
            break

        # 投递一批
        batch_end = min(idx + batch_size, total)
        for i in range(idx, batch_end):
            q.put(ip_source_list[i])  # (ip, source_url) 元组

        idx = batch_end

        # 等待这批完成：通过检查 _done_cnt 直到达到预期值
        expected_done = batch_end
        while _done_cnt[0] < expected_done and (not allow_early_stop or not _early_stop_flag[0]):
            time.sleep(0.1)

        # 触发本批次的增量测速（只在有新完成的 IP 时）
        if _done_cnt[0] > last_batch_done and len(results) > 0:
            incremental_batch_speed_test(results, batch_size=batch_size, target_pass_total=20,
                                         allow_early_stop=allow_early_stop)
            last_batch_done = _done_cnt[0]

    # 等队列清空
    q.join()
    log("INFO", "==== Probing DONE ====")

    # 发送停止信号
    for _ in ts:
        q.put(None)
    for t in ts:
        t.join()

    # _rank_by_speed 已移至 main() 统一调用

def main():
    """主入口：拉取数据源 → 两阶段探测 → 速度复测 → 上报 → 可选同步阿里云 DNS"""
    # 启动前校验 full 模式配置
    if not ORIGIN_SNI_LIST or not ORIGIN_TEST_PATH:
        log("ERROR", "ORIGIN_SNI_LIST 和 ORIGIN_TEST_PATH 不能为空！请检查脚本顶部配置。")
        sys.exit(1)
    log("INFO", f"mode={PROBE_MODE} SNI={ORIGIN_SNI_LIST} path={ORIGIN_TEST_PATH} verify={ORIGIN_VERIFY_CERT}")

    # 1. 获取历史优结果 (HAVE_POST_RES) - 优先级最高
    have_post_res_list = fetch_have_post_res()
    log("INFO", f"HAVE_POST_RES: {len(have_post_res_list)} items fetched")

    # 2. 获取第三方 IP (IP_SET_URLS) - 优先级中等
    wetest_ip_sources = fetch_wetest_ips()
    log("INFO", f"Priority-2 (IP_SET_URLS): {len(wetest_ip_sources)} IPs to probe")

    # 3. 获取域名列表并解析 DNS (DOMAINS_SET_URL) - 优先级最低
    domains = fetch_domains()
    domains = list(dict.fromkeys(domains))
    domain_ip_sources = resolve_domains_concurrent(domains, max_workers=40)
    log("INFO", f"Priority-3 (DOMAINS_SET_URL): {len(domain_ip_sources)} IPs from DNS resolution")

    # 4. 按历史测速成绩分组：speed >= LOWEST_SPEED*0.5 的 IP 进入 Phase 1
    speed_threshold = LOWEST_SPEED * 0.5
    priority_ips = [(ip, url) for ip, url, speed in have_post_res_list if speed >= speed_threshold]
    log("INFO", f"Phase-1 priority IPs (speed >= {speed_threshold}KB/s): {len(priority_ips)}")

    # 非优先级 IP：历史低分 + wetest + 域名解析 IP，按优先级去重
    seen = set()
    for ip, _ in priority_ips:
        seen.add(ip)

    remaining_ips = []
    # 历史优结果中未达标的
    for ip, url, _ in have_post_res_list:
        if ip not in seen:
            seen.add(ip)
            remaining_ips.append((ip, url))
    # wetest IP
    for ip, url in wetest_ip_sources:
        if ip not in seen:
            seen.add(ip)
            remaining_ips.append((ip, url))
    # 域名解析 IP
    for ip, url in domain_ip_sources:
        if ip not in seen:
            seen.add(ip)
            remaining_ips.append((ip, url))

    log("INFO", f"Phase-2 remaining IPs: {len(remaining_ips)}")
    log("INFO", f"Total IPs to probe: {len(priority_ips) + len(remaining_ips)}")

    results = []

    # Phase 1: 优先级 IP 探测（禁用早停）
    if priority_ips:
        _run_probe_phases(priority_ips, results, allow_early_stop=False)
        log("INFO", f"Phase-1 done: {len(results)} valid results")

        # Phase 1 全量测速
        _full_batch_speed_test(results)
        log("INFO", f"Phase-1 speed test done")

    # Phase 2: 其余 IP 探测（启用早停）
    if remaining_ips:
        _run_probe_phases(remaining_ips, results, allow_early_stop=True)
        log("INFO", f"Phase-2 done: {len(results)} valid results")

    # 统一速度排名赋分
    _rank_by_speed(results)

    log("INFO", f"Total IPs probed={len(priority_ips) + len(remaining_ips)} valid={len(results)} fail={_fail_cnt[0]}")

    # 5. 上报所有探测结果
    post_all_results(results)

    # 6. 最终选优：只从测速达标的 IP 中按速度排名选取
    speed_confirmed = [r for r in results if r.get('download_speed', 0) >= LOWEST_SPEED]

    if speed_confirmed:
        log("INFO", f"Final selection: {len(speed_confirmed)} IPs have completed speed test")
        # 从已测速 IP 中按区域选取
        top_n_res = (
            top_region(speed_confirmed, colo="HKG", topN=8) +
            top_region(speed_confirmed, region="NorthAmerica", topN=8) +
            top_region(speed_confirmed, region="EastAsia", topN=8)
        )
        top_n_res = select_top(top_n_res, 10)
    else:
        # 没有 IP 完成测速，回退到所有结果
        log("WARN", "No IPs have completed speed test, falling back to all results")
        top_n_res = (
            top_region(results, colo="HKG", topN=8) +
            top_region(results, region="NorthAmerica", topN=8) +
            top_region(results, region="EastAsia", topN=8)
        )
        top_n_res = select_top(top_n_res, 10)

    print_top_results(top_n_res)

    #更改aliyun DNS
    if CHANGE_DNS_RESOLVE:
        for cfg in ALI_DNS_TARGETS:
            send_to_aliyunDNS([r["real_ip"] for r in top_n_res], cfg["domain"])

if __name__ == "__main__":
    main()