#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudflareBestIP 配置文件模板。
复制为 config.py 并填入真实值。
"""
from datetime import datetime

def _today():
    return datetime.now().strftime("%Y%m%d")

# ================= 接口地址 =================
DOMAINS_SET_URL = "https://la.pingshaisland.top/api/domainsCT"
POST_URLS = [
    "https://pingshaisland.top/api/domains/dell",
    "https://la.pingshaisland.top/api/domains/dell",
    f"https://pingshaisland.top/api/domains/dell{_today()}",
    f"https://la.pingshaisland.top/api/domains/dell{_today()}",
]
IP_SET_URLS = [
    "https://www.wetest.vip/page/cloudflare/address_v4.html",
    "https://www.wetest.vip/page/cloudflare/total_v4.html",
    "https://www.wetest.vip/page/cloudflare/colo.html",
    "https://api.uouin.com/cloudflare.html",
    "https://v2rayssr.com/cfip/",
    "https://api.4ce.cn/api/bestCFIP",
    "https://vps789.com/public/sum/cfIpApi",
    "https://la.pingshaisland.top/api/domains/shayuan",
    "https://la.pingshaisland.top/api/domains/dell",
    "https://la.pingshaisland.top/api/domains/cgb",
    "https://la.pingshaisland.top/api/domains/jujule",
    "https://la.pingshaisland.top/api/domains/iphone",
    "https://pingshaisland.top/api/domains/shayuan",
    "https://pingshaisland.top/api/domains/dell",
    "https://pingshaisland.top/api/domains/cgb",
    "https://pingshaisland.top/api/domains/jujule",
    "https://pingshaisland.top/api/domains/iphone",
]

# ================= 探测参数 =================
SLEEP_INTERVAL = 300          # 单次探测间隔（毫秒）
TIMEOUT        = 7            # 单次探测超时（秒）
PROBE_REPEAT   = 2            # 每个 IP 重复探测次数
PROG_INTERVAL  = 10           # 进度日志间隔
TOP_N          = 10           # 最终输出 TOP N
LOWEST_SPEED   = 500          # 最低速度 KB/s

# ================= 计分权重 =================
WEIGHT_LATENCY  = 1
WEIGHT_LOSS     = 1
LOSS_PENALTY_MS = 3000

# ================= 探测模式与源站配置 =================
PROBE_MODE = "full"                       # "edge" | "full"
ORIGIN_SNI_LIST = [                       # 必填：真实源站域名（SNI+Host）
    "la.pingshaisland.top",
    "seattle.pingshaisland.top",
]
ORIGIN_TEST_PATH      = "/test.bin"       # 必填：源站延迟测试文件路径
ORIGIN_SPEED_TEST_PATH = "/test10MB.bin"  # 必填：源站速度测试文件路径
ORIGIN_VERIFY_CERT    = False             # 是否验证 TLS 证书

# ================= 阿里云 DNS 配置 =================
CHANGE_DNS_RESOLVE    = False             # 是否更新阿里云 DNS 解析
ALI_ACCESS_KEY_ID     = "your-access-key-id"
ALI_ACCESS_KEY_SECRET = "your-access-key-secret"
ALI_DNS_ENDPOINT      = "alidns.cn-hangzhou.aliyuncs.com"
ALI_DNS_TTL           = 605
ALI_DNS_MAX_RETRY     = 20
ALI_DNS_TARGETS = [
    {"domain": "jujule.pingshaisland.top"},
    {"domain": "shayuan.pingshaisland.top"},
]
