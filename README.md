# CloudflareBestIP — AI 阅读指南

## 项目概述

探测本地到 Cloudflare CDN 边缘节点的延迟和可用性，选出最优 IP 并同步到阿里云 DNS。

| 文件 | 用途 |
|------|------|
| `QwenGetBestIPs.py` | 主探测脚本（纯 Python socket+SSL，跨平台，无外部依赖） |
| `config.py` | 运行配置（含接口地址、探测参数、阿里云 DNS 密钥等） |
| `config.example.py` | 配置模板（可提交 git，不含密钥） |
| `GetBestDomains.bat` | Windows 一键启动批处理（可选，需自行修改路径） |

## 首次运行指南

### 1. 环境要求

- Python 3.8+
- 无需额外 pip 安装依赖（仅使用标准库 socket、ssl、json 等）
- 如需同步阿里云 DNS，则需 `pip install alibabacloud_alidns20150109`

### 2. 配置

```bash
cp config.example.py config.py   # 复制模板为正式配置
```

然后编辑 `config.py`，**必填项**：

| 必须配置 | 说明 |
|----------|------|
| `ORIGIN_SNI_LIST` | 你的源站域名（SNI + Host），至少填一个 |
| `ORIGIN_TEST_PATH` | 源站上的延迟测试文件路径，如 `/test.bin` |
| `ORIGIN_SPEED_TEST_PATH` | 源站上的速度测试文件路径，如 `/test10MB.bin` |
| `DOMAINS_SET_URL` | 域名列表 API 地址 |
| `POST_URLS` | 探测结果上报地址，至少一个 |

其余配置（探测参数、计分权重等）有默认值，可直接使用。

### 3. 运行

```bash
# Linux / macOS / Windows 通用
python QwenGetBestIPs.py

# Windows 也可双击 GetBestDomains.bat（需先修改其中的 Python 和脚本路径）
```

### 4. 输出

- 终端实时打印探测进度和最终 TOP 结果
- 日志写入 `YYYYMMDD_cf_test.log`
- 命中结果写入 `YYYYMMDD_cf_hits.csv`

## 阿里云 DNS 同步（可选）

**DNS 变更是一个可开关的附加功能，不配置完全不影响 Cloudflare IP 优选的核心结果。**

核心流程 `拉取数据源 → 探测 → 评分 → 输出 TOP` 不依赖任何 DNS 配置。`send_to_aliyunDNS()` 只在 `CHANGE_DNS_RESOLVE = True` 时才执行。

如需开启，额外配置以下项：

| 配置项 | 说明 |
|--------|------|
| `CHANGE_DNS_RESOLVE` | 设为 `True` 开启 DNS 同步 |
| `ALI_ACCESS_KEY_ID` | 阿里云 AccessKey ID |
| `ALI_ACCESS_KEY_SECRET` | 阿里云 AccessKey Secret |
| `ALI_DNS_TARGETS` | 要同步的域名列表 |

默认 `CHANGE_DNS_RESOLVE = False`，即使不填任何阿里云配置也不会报错。

## 核心流程

```
拉取数据源(domains + IPs) → DNS解析域名 → 去重合并 → 多线程并发探测 → 评分排序 → 上报结果 → 可选同步阿里云DNS
```

## QwenGetBestIPs.py 架构

### 两种探测模式

- **`PROBE_MODE = "full"`**: 同一条 TLS 连接上先请求 `/cdn-cgi/trace` 获取 colo（数据中心代码），再请求 `ORIGIN_TEST_PATH` 测试文件测延迟。返回 TCP/TLS/TTFB 分层耗时。
- **`PROBE_MODE = "edge"`**: 仅请求 `/cdn-cgi/trace`，以整体往返时间作为延迟，同时获取 colo。更轻量。

### 关键函数调用链

```
main()
 ├─ fetch_domains() + fetch_wetest_ips()        ── 并行拉取
 ├─ resolve_domains_concurrent(domains)          ── 并发 DNS 解析
 ├─ _run_probe_phases(all_ips, results)          ── 多线程探测
 │   └─ worker() → probe_target_full()
 │       └─ resolve_remote_ip()                  ── DNS 解析链
 │       └─ _probe_single_ip()                   ── 单 IP 多次探测 + 打分
 │           ├─ [full] probe_full_path()          ── TCP+TLS+HTTP 全链路
 │           │   └─ 同连接获取 colo (trace请求)
 │           └─ [edge] fetch_colo_from_trace()    ── 仅 trace 测延迟+colo
 ├─ test_download_speed()                        ── 速度复测
 ├─ post_all_results()                           ── 结果上报
 └─ send_to_aliyunDNS()                          ── 更新 DNS
```

### 评分公式

```python
# 阈值惩罚级
if tcp_loss > 0.2: return 999999   # TCP 失败率 >20% 直接淘汰
if tls_loss > 0.2: return 999999   # TLS 失败率 >20% 直接淘汰
# 综合评分（越低越好）
score = avg_lat * WEIGHT_LATENCY + http_loss * LOSS_PENALTY_MS * WEIGHT_LOSS
```

延迟取 **去尾均值**（去掉最大值），样本数 ≥3 时才去尾，避免单样本变空列表。

### DNS 解析链

```
腾讯 DoH (doh.pub) → 阿里 DoH (dns.alidns.com) → dig@223.6.6.6 → nslookup@223.6.6.6
```
所有方法过滤 Clash fake-ip 段 `198.18.x.x`。

### 已实现的优化

- **并行数据源拉取**: `fetch_domains()` 和 `fetch_wetest_ips()` 并行执行；22 个 IP 源 URL 用 `ThreadPoolExecutor` 并发抓取
- **colo 缓存**: full 模式下同 IP 只获取一次 colo，写入 `_colo_cache`（edge 模式不缓存，因为 trace 请求本身就是延迟测量）
- **recv 缓冲区**: 128KB（与测试文件下载量匹配）
- **HTTP 指纹**: 统一使用 Chrome 128 请求头常量 `_HTTP_FINGERPRINT`，通过 `_build_request()` 组装
- **colo 与延迟同一连接**: `probe_full_path` 在 TLS 握手后先发 trace 拿 colo（keep-alive），再发测试文件请求（close），省掉一次 TCP+TLS

### 配置速查

所有运行配置集中在 `config.py`（从 `config.example.py` 复制后修改）。

**必填项：**

| 配置项 | 说明 |
|--------|------|
| `ORIGIN_SNI_LIST` | 源站域名列表（SNI + Host） |
| `ORIGIN_TEST_PATH` | 延迟测试文件路径 |
| `ORIGIN_SPEED_TEST_PATH` | 速度测试文件路径（10MB） |
| `DOMAINS_SET_URL` | 域名列表 API |
| `POST_URLS` | 结果上报 URL 列表 |

**可选调整：**

| 配置项 | 说明 |
|--------|------|
| `PROBE_MODE` | `"full"` 全链路 或 `"edge"` 仅 colo |
| `ORIGIN_VERIFY_CERT` | 是否验证 TLS 证书 |
| `SLEEP_INTERVAL` | 探测间隔（秒），默认 300 秒=5 分钟 |
| `TIMEOUT` | 单次探测超时（秒） |
| `PROBE_REPEAT` | 每个 IP 重复探测次数 |
| `LOWEST_SPEED` | 最低速度阈值 KB/s |
| `WEIGHT_LATENCY / WEIGHT_LOSS / LOSS_PENALTY_MS` | 计分权重 |
| `IP_SET_URLS` | IP 数据源 URL 列表 |

**阿里云 DNS（可选，不填不影响优选结果）：**

| 配置项 | 说明 |
|--------|------|
| `CHANGE_DNS_RESOLVE` | `False` 关闭 / `True` 开启 |
| `ALI_ACCESS_KEY_ID / ALI_ACCESS_KEY_SECRET` | 阿里云 AK/SK |
| `ALI_DNS_TARGETS` | 要更新的域名列表 |

## 数据源

`IP_SET_URLS` 从 wetest.vip、uouin.com、v2rayssr.com、4ce.cn、vps789.com 及 pingshaisland.top 各子 API 抓取 Cloudflare IP 段。

## 已知陷阱

1. **`PROBE_MODE="full"` 时 colo 为 None 必须 return**：`probe_full_path` 成功但 trace 请求可能失败。之前漏掉 `return None` 导致 `None + ":"` 崩溃。
2. **去尾均值单样本问题**：`sorted_lat[:-1]` 在只有 1 个样本时得空列表 → `sum([])/0` 崩溃。已修复为 ≥3 样本才去尾。
3. **DNS 解析顺序**：腾讯 DoH 是境外服务，国内环境可能超时，阿里 DoH 作为二选，最后才用系统的 dig/nslookup。
4. **config.py 不提交到 git**：`.gitignore` 排除 `config.py`。首次使用需 `cp config.example.py config.py` 后修改。

## 修改注意事项

- 改配置项：编辑 `config.py`，新增配置需同步更新 `config.example.py`（脱敏版）
- 改 `_HTTP_FINGERPRINT` 常量会影响所有出站请求的指纹
- 改 `probe_full_path` 时注意测试文件下载的速率检查逻辑（每 50 个 recv 检查一次 `LOWEST_SPEED`）
- 线程安全：`_colo_cache`、`_tested_ips`、`_done_cnt`、`_fail_cnt` 均有独立锁保护
- worker 线程的 `task_done()` 必须在 `finally` 块中调用，否则队列 join 死锁
