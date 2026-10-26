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
import http.client
import io
import math
from functools import lru_cache
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
def _http_get(url, timeout=15, headers=None):
    """HTTP GET 请求：优先 curl，失败回退 urllib；返回响应字节或 None"""
    if HAS_CURL:
        try:
            args = [CURL_BIN, "-sf", "--max-time", str(timeout)]
            for key, value in (headers or {}).items():
                args.extend(["-H", f"{key}: {value}"])
            r = subprocess.run(args + [url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout+3)
            if r.returncode == 0: return r.stdout
        except Exception: pass
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp: return resp.read()
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
                    [CURL_BIN, "-sf", "--max-time", str(timeout), "-X", "POST", url,
                     "-H", "Content-Type: application/json",
                     "-d", f"@{tmp_path}"],
                    timeout=timeout,
                    capture_output=True,   # 捕获输出以便检查错误
                    text=True, encoding="utf-8", errors="replace"
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
    """从 DOMAINS_SET_URL 拉取域名；源不可用时允许其他 IP 来源继续工作。"""
    if not DOMAINS_SET_URL:
        return []
    for attempt in range(1, max_retry + 1):
        raw = _http_get(DOMAINS_SET_URL)
        if raw:
            try:
                data = json.loads(raw.decode())
                if isinstance(data, list):
                    domains = [str(x).strip() for x in data if str(x).strip()]
                    log("INFO", f"GET domains count={len(domains)}"); return domains
            except Exception as e: log("WARN", f"parse domains fail {attempt}: {e}"); time.sleep(2*attempt)
    log("WARN", "GET domains failed; continuing with other IP sources")
    return []

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
    """Serialize cache initialization, including API/fallback loading."""
    with _cf_cidr_lock:
        return _load_cloudflare_cidrs()


def _load_cloudflare_cidrs():
    """
    获取 Cloudflare IPv4 CIDR 列表。
    1. 内存缓存（已加载则直接返回）
    2. API 请求
    3. 失败则使用 config.CF_DEFAULT_IPV4_CIDRS
    返回 ipaddress.IPv4Network 对象列表。
    """
    global _cf_ipv4_cidrs
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

    log("ERROR", "No CF CIDRs available; cannot validate candidate IPs")
    _cf_ipv4_cidrs = []
    return _cf_ipv4_cidrs

def is_cf_ip(ip_str):
    """
    判断单个 IPv4 地址是否属于 Cloudflare 网段。
    使用标准库 ipaddress 模块进行 CIDR 匹配。
    没有网段规则时不接受未经验证的 IP。
    """
    global _cf_ipv4_cidrs
    if not _cf_ipv4_cidrs:
        return False
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in cidr for cidr in _cf_ipv4_cidrs)
    except ValueError:
        return False  # 非法 IP 地址直接拒绝

def filter_cf_ips(ips_list):
    """
    只保留 Cloudflare 网段的 IP，稳定去重。内存中的网段匹配无需线程池。
    """
    if not ips_list:
        return []

    # 确保先加载 CIDR 规则（但不会阻塞太久）
    fetch_cloudflare_cidrs()

    filtered = [ip for ip in dict.fromkeys(ips_list) if is_cf_ip(ip)]

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
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            if not is_ip(ip):
                continue
            try:
                speed = float(item.get("speed_kb_s") or 0)
            except (ValueError, TypeError):
                speed = 0
            if not math.isfinite(speed) or speed < 0:
                speed = 0
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
    urls = list(dict.fromkeys(HAVE_POST_RES + POST_URLS))
    if not urls:
        log("INFO", "No history URLs, skip")
        return []

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
    valid_ips = filter_cf_ips(list(ip_best))
    result_list = [(ip, ip_best[ip][0], ip_best[ip][1]) for ip in valid_ips]
    result_list.sort(key=lambda x: x[2] if x[2] > 0 else float('-inf'), reverse=True)

    log("INFO", f"HAVE_POST_RES: raw={len(all_results)}, deduped={len(result_list)} items (sorted by speed_kb_s DESC)")
    return result_list

def fetch_wetest_ips():
    """并发从所有 IP_SET_URLS 抓取 IPv4 地址，过滤非 Cloudflare 网段，返回 [(ip, source_url), ...]"""
    ip_source = {}  # ip -> source_url
    urls = IP_SET_URLS
    if not urls:
        return []
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
    if not isinstance(s, str):
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False

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
    try:
        raw = _http_get(url, timeout=5, headers={"accept": "application/dns-json"})
        if not raw:
            return []
        data = json.loads(raw.decode("utf-8"))
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
@lru_cache(maxsize=2)
def _ssl_context(verify_cert):
    """Reuse immutable SSL contexts instead of loading CA roots for every sample."""
    ctx = ssl.create_default_context()
    if not verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _create_tls_socket(ip, domain, timeout, verify_cert=False):
    """创建 TLS 连接到 IP:443，返回 (raw_socket, ssl_socket)"""
    sock = socket.create_connection((ip, 443), timeout=timeout)
    try:
        return sock, _ssl_context(verify_cert).wrap_socket(sock, server_hostname=domain)
    except Exception:
        sock.close()
        raise


class _ResponseStream(io.RawIOBase):
    """Time the first received byte and enforce a deadline on every socket read."""
    def __init__(self, ssock, timeout, started):
        super().__init__()
        self.ssock = ssock
        self.timeout = timeout
        self.deadline = started + timeout
        self.first_byte_at = None

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.perf_counter()
        if remaining <= 0:
            raise socket.timeout("HTTP response deadline exceeded")
        self.ssock.settimeout(min(self.timeout, remaining))
        chunk = self.ssock.recv(len(buffer))
        if chunk and self.first_byte_at is None:
            self.first_byte_at = time.perf_counter()
        buffer[:len(chunk)] = chunk
        return len(chunk)

    def makefile(self, mode):
        return io.BufferedReader(self, buffer_size=64 * 1024)


def _open_response(ssock, request, timeout):
    started = time.perf_counter()
    stream = _ResponseStream(ssock, timeout, started)
    ssock.settimeout(timeout)
    ssock.sendall(request)
    response = http.client.HTTPResponse(stream)
    try:
        response.begin()
    except Exception:
        response.close()
        raise
    return response, stream, started

def _parse_colo(data):
    """从 /cdn-cgi/trace 响应字节中解析 colo 值，未找到返回 None"""
    for line in data.decode(errors="ignore").splitlines():
        if line.startswith("colo="):
            return line.split("=", 1)[1].strip()
    return None

def fetch_colo_from_trace(ip, domain="la.pingshaisland.top", timeout=10):
    """探测 /cdn-cgi/trace 获取 colo（纯网络测量，无缓存）"""
    sock = ssock = response = None
    try:
        sock, ssock = _create_tls_socket(ip, domain, timeout, ORIGIN_VERIFY_CERT)
        response, _, _ = _open_response(ssock, _build_request("GET", "/cdn-cgi/trace", domain, "close"), timeout)
        if response.status == 200:
            return _parse_colo(response.read(64 * 1024))
    except Exception:
        return None
    finally:
        if response:
            response.close()
        if ssock:
            ssock.close()
        if sock:
            try: sock.close()
            except OSError: pass

def probe_full_path(ip, domain, test_path="/test.bin", timeout=3):
    """Measure TCP/TLS/first-byte latency; download the body only for speed tests."""
    res = dict(success=False, ttfb_ms=None, tcp_ms=None, tls_ms=None,
               total_ms=None, colo=None, error=None, download_speed=0,
               download_bytes=0, download_cost_time=0)
    t_start = time.perf_counter()
    sock = ssock = response = None
    stage = "TCP"
    try:
        ctx = _ssl_context(ORIGIN_VERIFY_CERT)
        t0 = time.perf_counter()
        sock = socket.create_connection((ip, 443), timeout=timeout)
        res['tcp_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        stage = "TLS"
        t0 = time.perf_counter()
        ssock = ctx.wrap_socket(sock, server_hostname=domain)
        res['tls_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        stage = "HTTP"
        with _colo_cache_lock:
            res['colo'] = _colo_cache.get((ip, domain))
        if not res['colo']:
            response, _, _ = _open_response(
                ssock, _build_request("GET", "/cdn-cgi/trace", domain, "keep-alive"), min(timeout, 3))
            if response.status != 200:
                raise ValueError(f"trace HTTP {response.status}")
            trace = response.read(64 * 1024 + 1)
            res['colo'] = _parse_colo(trace)
            if len(trace) > 64 * 1024 or not res['colo']:
                raise ValueError("invalid trace response")
            should_reconnect = response.will_close
            response.close()
            response = None
            with _colo_cache_lock:
                _colo_cache[(ip, domain)] = res['colo']
            if should_reconnect:
                ssock.close()
                sock.close()
                # Some servers close trace connections; measure the new connection.
                stage = "TCP"
                res['tcp_ms'] = res['tls_ms'] = None
                t0 = time.perf_counter()
                sock = socket.create_connection((ip, 443), timeout=timeout)
                res['tcp_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                stage = "TLS"
                t0 = time.perf_counter()
                ssock = ctx.wrap_socket(sock, server_hostname=domain)
                res['tls_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                stage = "HTTP"

        measure_speed = test_path == ORIGIN_SPEED_TEST_PATH
        response_timeout = min(timeout, 10) if measure_speed else timeout
        separator = "&" if "?" in test_path else "?"
        request = _build_request("GET", f"{test_path}{separator}t={time.time_ns()}", domain, "close",
                                 extra_headers="Cache-Control: no-cache, no-store\r\n")
        response, stream, started = _open_response(ssock, request, response_timeout)
        res['ttfb_ms'] = round((stream.first_byte_at - started) * 1000, 1)
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        if measure_speed:
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("compressed speed test response")
            body_size = 0
            expected_size = response.length
            while True:
                try:
                    chunk = response.read1(64 * 1024)
                except socket.timeout:
                    if body_size and time.perf_counter() >= stream.deadline:
                        break  # A bounded sample need not download the entire file.
                    raise
                if not chunk:
                    if expected_size is not None and body_size < expected_size:
                        raise ValueError("truncated response body")
                    break
                body_size += len(chunk)
                elapsed = time.perf_counter() - started
                if elapsed >= response_timeout:
                    break
                if elapsed >= 5:
                    speed = body_size / 1024 / elapsed
                    if speed > LOWEST_SPEED * 1.1 or speed < LOWEST_SPEED * 0.6:
                        break
            if not body_size:
                raise ValueError("empty speed test body")
            elapsed = max(time.perf_counter() - started, 0.000001)
            res['download_bytes'] = body_size
            res['download_cost_time'] = round(elapsed * 1000, 1)
            res['download_speed'] = round(body_size / 1024 / elapsed, 1)
        res['success'] = True
    except Exception as e:
        res['error'] = f"{stage}:{e}"
        log("WARN", f"ip={ip} {res['error']}")
    finally:
        res['total_ms'] = round((time.perf_counter() - t_start) * 1000, 1)
        if response:
            response.close()
        if ssock:
            ssock.close()
        if sock:
            sock.close()
    return res

# ================= HTTP 指纹 =================
_HTTP_FINGERPRINT = (
    "User-Agent:Chrome/128.0.0.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
    "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
    "Accept-Encoding: identity\r\n"
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
                tcp_ok += res.get('tcp_ms') is not None
                tls_ok += res.get('tls_ms') is not None
                if not res['success']:
                    log("WARN", f"ip={real_ip} probe_full_path failed for {sni}: {res.get('error', 'unknown')}")
                    continue
                colo = res.get('colo')
                if colo:
                    with _colo_cache_lock:
                        _colo_cache[(real_ip, sni)] = colo
                if not colo:
                    log("WARN", f"ip={real_ip} colo is UNKNOWN after probe_full_path for {sni}")
                    colo = "UNKNOWN"
                http_ok += 1
                latency = round(res['tcp_ms'] + res['tls_ms'] + res['ttfb_ms'], 1)
                latencies.append(latency)
                each_probe_info.append(colo+":"+str(latency)+"ms")
                last_tcp_ms = res.get('tcp_ms', 0)
                last_tls_ms = res.get('tls_ms', 0)
                last_ttfb_ms = res.get('ttfb_ms', 0)
                last_total_ms = res.get('total_ms', 0)
            else:
                t0 = time.perf_counter()
                colo = fetch_colo_from_trace(real_ip, sni, timeout=TIMEOUT)
                if not colo:
                    log("WARN", f"ip={real_ip} failed to get colo (edge mode) for {sni}")
                    continue
                latency = round((time.perf_counter() - t0) * 1000, 1)
                latencies.append(latency)
                tcp_ok += 1
                tls_ok += 1
                http_ok += 1
                each_probe_info.append(colo+":"+str(latency)+"ms")

    if not latencies:
        return None
    sorted_lat = sorted(latencies)
    trimmed_lat = sorted_lat[:-1] if len(sorted_lat) >= 3 else sorted_lat
    avg_lat = round(sum(trimmed_lat) / len(trimmed_lat), 1) if trimmed_lat else 9999
    tcp_loss = 1 - (tcp_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    tls_loss = 1 - (tls_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    http_loss = 1 - (http_ok / (PROBE_REPEAT*len(ORIGIN_SNI_LIST)))
    score = round(_score(avg_lat, tcp_loss, tls_loss, http_loss), 1)

    if score >= 999999:
        log("WARN", f"ip={real_ip} discarded: tcp_loss={tcp_loss} tls_loss={tls_loss} (score={score})")
        return None

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
        d = q.get()
        try:
            if d is None:
                log("INFO", f" received STOP signal, exiting")
                break

            # 检查是否已提前终止（仅当 allow_early_stop=True 时检查）
            if allow_early_stop and _early_stop_flag[0]:
                continue

            # 任务可能是 (ip, source_url) 元组或单个 target
            if isinstance(d, tuple) and len(d) == 2:
                target, source_url = d
            else:
                target, source_url = d, None

            # 执行探测
            plist = probe_target_full(target, source_url)

            with _done_lock:
                results.extend(plist)
                if not plist:
                    _fail_cnt[0] += 1
        except Exception as e:
            log("ERROR", f" worker crashed: {type(e).__name__}: {e}")
            with _done_lock:
                _fail_cnt[0] += 1
        finally:
            if d is not None:
                with _done_lock:
                    _done_cnt[0] += 1
                    if _done_cnt[0] % PROG_INTERVAL == 0:
                        log("PROG", f"tested={_done_cnt[0]} hits={len(results)} fail={_fail_cnt[0]}")
            q.task_done()  # Exactly once, including skipped jobs and sentinels.

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
        log("FINAL", f'{r["real_ip"]} (from {r["target"]}) -> {r["colo"]} lat={r["lat"]}ms loss={r["loss"]} speed={r.get("download_speed", 0)}KB/s score={r["score"]}')

def post_all_results(results):
    """将探测结果转为 JSON 并并发 POST 到所有上报地址（含来源 URL、分层耗时、速度等完整字段）"""
    if not results: return
    nodes = []
    skipped = 0
    for r in sorted(results, key=lambda x: x.get("score", 999999)):
        ip   = (r.get("real_ip") or "").strip()
        colo = (r.get("colo") or "").strip().upper()
        score = r.get("score", 999999)
        if not ip:
            skipped += 1
            continue
        if not colo or colo in ("UNKNOWN", "NONE", "NULL"):
            skipped += 1
            continue
        if score is None or score >= 9999:
            skipped += 1
            continue
        nodes.append({
            "ip": ip,
            "colo": colo,
            "score": score,
            "lat": r.get("lat") or 0,
            "loss": r.get("loss") or 0,
            "source": r.get("source_url") or "",
            "speed_kb_s": r.get("download_speed") or 0,
            "tcp_ms": r.get("tcp_ms") or 0,
            "tls_ms": r.get("tls_ms") or 0,
            "ttfb_ms": r.get("ttfb_ms") or 0,
            "total_ms": r.get("total_ms") or 0
        })
    if skipped:
        log("INFO", f"post_all_results: skipped {skipped} invalid nodes")
    if not nodes:
        return
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

def _speed_passes(result):
    """One eligibility rule for early stop, ranking, output and DNS selection."""
    speed = result.get("download_speed", 0)
    return (math.isfinite(speed) and speed >= LOWEST_SPEED
            and is_ip(result.get("real_ip"))
            and result.get("colo") not in (None, "", "UNKNOWN")
            and result.get("tcp_loss", 0) <= 0.2
            and result.get("tls_loss", 0) <= 0.2)


def _measure_speed(result):
    """Measure each IP once; failed samples remain failed rather than being retried implicitly."""
    if result.get("speed_tested") or result.get("download_speed", 0) > 0:
        return False
    result["speed_tested"] = True
    sample = probe_full_path(result['real_ip'], ORIGIN_SNI_LIST[0],
                             test_path=ORIGIN_SPEED_TEST_PATH, timeout=10)
    result['download_speed'] = sample.get('download_speed', 0) if sample['success'] else 0
    result['download_cost_time'] = sample.get('download_cost_time', 0)
    if _speed_passes(result):
        _speed_pass_count[0] += 1
    log("INFO", f"SPEED ip={result['real_ip']} speed={result['download_speed']}KB/s success={sample['success']}")
    return sample['success']


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
        candidates = [r for r in results if not r.get('speed_tested') and not r.get('download_speed', 0)]
        # 从本批未测速的结果中选取三区域各 Top5，其余区域补足到 15 个。
        try:
            na_top = top_region(candidates, region="NorthAmerica", topN=5)
            hk_top = top_region(candidates, colo="HKG", topN=5)
            ea_top = top_region(candidates, region="EastAsia", topN=5)
        except ValueError:
            return 0  # 结果不足

        # 合并去重（避免同一 IP 出现在多个区域被重复测速）
        tested_ips = set()
        batch_to_test = []
        for r in na_top + hk_top + ea_top + select_top(candidates, 15):
            if r['real_ip'] not in tested_ips:
                tested_ips.add(r['real_ip'])
                batch_to_test.append(r)

        if not batch_to_test:
            return 0

        log("INFO", f"=== Incremental batch speed test: {len(batch_to_test)} IPs ===")

        # 对这批 IP 进行测速
        local_pass = 0
        for each in batch_to_test[:15]:
            if allow_early_stop and _speed_pass_count[0] >= target_pass_total:
                break
            if _measure_speed(each) and _speed_passes(each):
                local_pass += 1
                log("INFO", f"BATCH speed PASS: {_speed_pass_count[0]}/{target_pass_total}")

        # 检查是否已达到总目标（仅 allow_early_stop=True 时设置早停标志）
        if allow_early_stop and _speed_pass_count[0] >= target_pass_total:
            _early_stop_flag[0] = True
            log("INFO", f"=== Early stop triggered: {_speed_pass_count[0]} IPs passed speed test ===")

        return local_pass


def _full_batch_speed_test(results):
    """
    全量速度复测：对所有 results 中的 IP，逐个跑 ORIGIN_SPEED_TEST_PATH 速度测试。
    probe_full_path 内部已按实际字节/实际耗时算出 download_speed，直接取用。
    与 incremental_batch_speed_test 的区别：
    - 不抽样：全量遍历，不按区域选 Top
    - 不限制区域：所有 IP 都测
    - 不设置早停标志：纯测速
    """
    if not results:
        log("INFO", "_full_batch_speed_test: no results to test, skip")
        return 0

    log("INFO", f"=== Full batch speed test: {len(results)} IPs ===")
    tested_count = 0

    for each in _dedup_by_best_score(results):
        tested_count += bool(_measure_speed(each))

    passed = sum(_speed_passes(r) for r in results)
    log("INFO", f"_full_batch_speed_test done: {tested_count} tested, {passed} passed (>= {LOWEST_SPEED}KB/s)")
    return tested_count


def _rank_by_speed(results):
    """
    最终速度排名：对已完成测速的 IP，按 download_speed 降序排名赋分。
    - 测速达标 (>= LOWEST_SPEED)：score = 排名序号（1, 2, 3...）
    - 测速不达标 (< LOWEST_SPEED)：score = 9999 垫底
    - 未测速/测速失败：score = 9999，不参与最终 TOP/DNS
    """
    results.sort(key=lambda r: (not _speed_passes(r), -r.get('download_speed', 0), r['lat'], r['real_ip']))
    passed = 0
    for r in results:
        r['probe_score'] = r.get('probe_score', r['score'])
        if _speed_passes(r):
            passed += 1
            r['score'] = passed
        else:
            r['score'] = 9999
    log("INFO", f"_rank_by_speed: {passed} passed (>= {LOWEST_SPEED}KB/s)")


def _run_probe_phases(ip_source_list, results, allow_early_stop=True, do_incremental_speed_test=True):
    """
    只探测 IP 列表，每个 (ip, source_url) 作为一个独立任务。
    每完成 100 个 IP 的延迟测试后，触发一次增量批次测速（仅 do_incremental_speed_test=True 时）。
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

    try:
        while idx < total:
            if allow_early_stop and _early_stop_flag[0]:
                log("INFO", "Early stop detected, stopping probe...")
                break
            prev_results_len = len(results)
            batch_end = min(idx + batch_size, total)
            for i in range(idx, batch_end):
                q.put(ip_source_list[i])
            idx = batch_end
            q.join()  # Per-batch barrier; independent of previous phases and failures.
            if do_incremental_speed_test and len(results) > prev_results_len:
                incremental_batch_speed_test(results[prev_results_len:], batch_size=batch_size,
                                             target_pass_total=20, allow_early_stop=allow_early_stop)
    finally:
        for _ in ts:
            q.put(None)
        q.join()
        for t in ts:
            t.join()
    log("INFO", "==== Probing DONE ====")

    # _rank_by_speed 已移至 main() 统一调用

def _validate_config():
    if PROBE_MODE not in ("full", "edge"):
        raise ValueError('PROBE_MODE must be "full" or "edge"')
    if not ORIGIN_SNI_LIST or any(not isinstance(s, str) or not s.strip() for s in ORIGIN_SNI_LIST):
        raise ValueError("ORIGIN_SNI_LIST must contain valid hostnames")
    for path in (ORIGIN_TEST_PATH, ORIGIN_SPEED_TEST_PATH):
        if not isinstance(path, str) or not path.startswith("/") or "\r" in path or "\n" in path:
            raise ValueError("Origin test paths must start with / and contain no newlines")
    for name, value in (("PROBE_REPEAT", PROBE_REPEAT), ("TOP_N", TOP_N), ("PROG_INTERVAL", PROG_INTERVAL)):
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if TIMEOUT <= 0 or LOWEST_SPEED <= 0 or SLEEP_INTERVAL < 0:
        raise ValueError("TIMEOUT/LOWEST_SPEED must be positive; SLEEP_INTERVAL cannot be negative")


def _reset_run_state():
    _done_cnt[0] = _fail_cnt[0] = _speed_pass_count[0] = 0
    _early_stop_flag[0] = False
    with _tested_ips_lock:
        _tested_ips.clear()
    with _colo_cache_lock:
        _colo_cache.clear()


def main():
    """主入口：拉取数据源 → 两阶段探测 → 速度复测 → 上报 → 可选同步阿里云 DNS"""
    _validate_config()
    _reset_run_state()
    log("INFO", f"mode={PROBE_MODE} SNI={ORIGIN_SNI_LIST} path={ORIGIN_TEST_PATH} verify={ORIGIN_VERIFY_CERT}")

    # 1. 获取历史优结果 (HAVE_POST_RES) - 优先级最高
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        history_task = executor.submit(fetch_have_post_res)
        wetest_task = executor.submit(fetch_wetest_ips)
        domains_task = executor.submit(fetch_domains)
        have_post_res_list = history_task.result()
        wetest_ip_sources = wetest_task.result()
        domains = domains_task.result()
    log("INFO", f"HAVE_POST_RES: {len(have_post_res_list)} items fetched")

    # 2. 获取第三方 IP (IP_SET_URLS) - 优先级中等
    log("INFO", f"Priority-2 (IP_SET_URLS): {len(wetest_ip_sources)} IPs to probe")

    # 3. 获取域名列表并解析 DNS (DOMAINS_SET_URL) - 优先级最低
    domains = list(dict.fromkeys(domains))
    domain_ip_sources = resolve_domains_concurrent(domains, max_workers=40)
    log("INFO", f"Priority-3 (DOMAINS_SET_URL): {len(domain_ip_sources)} IPs from DNS resolution")

    # 4. 历史速度达到当前下限的 65% 时优先复测；最终达标仍须达到完整下限。
    speed_threshold = LOWEST_SPEED * 0.65
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
        _run_probe_phases(priority_ips, results, allow_early_stop=False, do_incremental_speed_test=False)
        log("INFO", f"Phase-1 done: {len(results)} valid results")

        # Phase 1 全量测速
        _full_batch_speed_test(results)
        log("INFO", f"Phase-1 speed test done")

    # Phase 2: 其余 IP 探测（启用早停），Phase-1 达标数够则跳过
    if remaining_ips:
        passed_after_p1 = sum(_speed_passes(r) for r in results)
        if passed_after_p1 >= 20:
            log("INFO", f"Phase-1 already has {passed_after_p1} qualified IPs; skipping Phase-2")
        else:
            _run_probe_phases(remaining_ips, results, allow_early_stop=True, do_incremental_speed_test=True)

    # 统一速度排名赋分
    _rank_by_speed(results)

    log("INFO", f"Total candidates={len(priority_ips) + len(remaining_ips)} tested={_done_cnt[0]} valid={len(results)} fail={_fail_cnt[0]}")

    # 5. 上报所有探测结果
    post_all_results(results)


    top_n_res = select_top([r for r in results if _speed_passes(r)], TOP_N)
    print_top_results(top_n_res)
    if not top_n_res:
        log("WARN", f"No IP meets LOWEST_SPEED={LOWEST_SPEED}KB/s; no DNS changes")
        return

    #更改aliyun DNS
    if CHANGE_DNS_RESOLVE:
        for cfg in ALI_DNS_TARGETS:
            send_to_aliyunDNS([r["real_ip"] for r in top_n_res], cfg["domain"])

if __name__ == "__main__":
    main()
