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
DOMAINS_SET_URL = "https://abc.top/api/domainsCT"       # 域名列表 API 地址
POST_URLS = [                                    # 探测结果上报地址列表
    "https://abc.top/api/domains/dell",
    "https://la.abc.top/api/domains/dell",
    f"https://abc.top/api/domains/dell{_today()}",
    f"https://la.abc.top/api/domains/dell{_today()}",
]
IP_SET_URLS = [                                  # Cloudflare IP 段数据源 URL 列表
    "https://www.wetest.vip/page/cloudflare/address_v4.html",
    "https://www.wetest.vip/page/cloudflare/total_v4.html",
    "https://www.wetest.vip/page/cloudflare/colo.html",
    "https://api.uouin.com/cloudflare.html",
    "https://v2rayssr.com/cfip/",
    "https://api.4ce.cn/api/bestCFIP",
    "https://vps789.com/public/sum/cfIpApi",
]

# ================= Cloudflare 默认 CIDR（API 失败时的后备配置）=================
CF_DEFAULT_IPV4_CIDRS = [                        # Cloudflare 官方 IPv4 CIDR 段（fallback 配置）
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

# ================= 探测参数 =================
SLEEP_INTERVAL = 300          # 单次探测间隔（秒），300秒=5分钟
TIMEOUT        = 7            # 单次探测超时（秒）
PROBE_REPEAT   = 2            # 每个 IP 重复探测次数
PROG_INTERVAL  = 10           # 进度日志间隔
TOP_N          = 10           # 最终输出 TOP N
LOWEST_SPEED   = 500          # 最低速度 KB/s

# ================= 计分权重 =================
WEIGHT_LATENCY  = 1          # 延迟在评分中的权重
WEIGHT_LOSS     = 1          # 丢包率在评分中的权重
LOSS_PENALTY_MS = 3000       # 每 1% 丢包的惩罚毫秒数

# ================= 探测模式与源站配置 =================
PROBE_MODE = "full"                       # "edge" | "full"
ORIGIN_SNI_LIST = [                       # 必填：真实源站域名（SNI+Host）
    "la.abc.top",
    "seattle.abc.top",
]
ORIGIN_TEST_PATH      = "/test.bin"       # 必填：源站延迟测试文件路径
ORIGIN_SPEED_TEST_PATH = "/test10MB.bin"  # 必填：源站速度测试文件路径
ORIGIN_VERIFY_CERT    = False             # 是否验证 TLS 证书

# ================= 阿里云 DNS 配置 =================
CHANGE_DNS_RESOLVE    = False             # 是否更新阿里云 DNS 解析
ALI_ACCESS_KEY_ID     = "your-access-key-id"                    # 阿里云 AccessKey ID
ALI_ACCESS_KEY_SECRET = "your-access-key-secret"                # 阿里云 AccessKey Secret
ALI_DNS_ENDPOINT      = "alidns.cn-hangzhou.aliyuncs.com"       # 阿里云 DNS API 端点
ALI_DNS_TTL           = 605                                     # DNS A 记录 TTL（秒）
ALI_DNS_MAX_RETRY     = 20                                      # 阿里云 DNS 更新最大重试次数
ALI_DNS_TARGETS = [                                             # 要同步更新的域名列表（每项含 domain 字段）
    {"domain": "jujule.abc.top"},
    {"domain": "shayuan.abc.top"},
]
