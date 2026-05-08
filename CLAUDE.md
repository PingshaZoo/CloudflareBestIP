# CloudflareBestIP — AI 阅读指南

## 项目概述

探测本地到 Cloudflare CDN 边缘节点的延迟和可用性，选出最优 IP 并同步到阿里云 DNS。包含两个独立脚本：

| 文件 | 探测方式 | 适用场景 |
|------|----------|----------|
| `QwenGetBestIPs.py` | 纯 Python socket+SSL（推荐） | 跨平台，无外部依赖 |
| `GetBestDomains.py` | curl `--resolve` + urllib fallback | 依赖 curl |

## 核心流程（两脚本通用）

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

### 配置段速查（QwenGetBestIPs.py）

| 配置 | 位置（行号附近） |
|------|-----------------|
| `PROBE_MODE` | 81 |
| `ORIGIN_SNI_LIST` | 83 |
| `ORIGIN_TEST_PATH` | 87 |
| `SLEEP_INTERVAL` | 67 |
| `TIMEOUT` | 68 |
| `PROBE_REPEAT` | 69 |
| `CONCURRENCY` | 108 |
| `WEIGHT_LATENCY / WEIGHT_LOSS / LOSS_PENALTY_MS` | 75-77 |
| `LOWEST_SPEED` | 72 |
| `TOP_N` | 71 |
| `IP_SET_URLS` | 45 |
| `POST_URLS` | 39 |
| `CHANGE_DNS_RESOLVE` | 92 |
| `ALI_DNS_TARGETS` | 98 |

## GetBestDomains.py 架构

### 与 QwenGetBestIPs.py 的关键差异

| 维度 | QwenGetBestIPs | GetBestDomains |
|------|---------------|----------------|
| 探测引擎 | 纯 Python socket+SSL | curl `--resolve` + urllib fallback |
| 延迟指标 | TCP/TLS/TTFB 分层 | `time_starttransfer`（首字节时间） |
| 数据源抓取 | ThreadPoolExecutor 并发 | 串行 for 循环 |
| DNS 解析 | 多方法 fallback 链 | DoH → dig/nslookup |
| 结果返回 | 成功返回所有 IP | 成功返回所有 IP（同样修复了返回单个的 bug） |
| fail-fast | 否（多次探测独立评分） | 是（任一次失败立即丢弃该 IP） |
| colo 名 | 英文 | 英文 |
| 下载测速 | 有 `test_download_speed()` | 无 |

### 探测方式

`probe_once_curl()`: `curl --resolve` 强制将域名解析到指定 IP，请求 `/cdn-cgi/trace`，用 `-w time_starttransfer` 计算延迟。

`probe_once_urllib()`: 自定义 `HTTPSConnection.connect()` 直连 IP，用 `time.perf_counter()` 计时。

## 数据源 URL 列表

两脚本的 `IP_SET_URLS` 基本相同，从 wetest.vip、uouin.com、v2rayssr.com、4ce.cn、vps789.com 及 pingshaisland.top 各子 API 抓取 Cloudflare IP 段。

## 已知陷阱

1. **`PROBE_MODE="full"` 时 colo 为 None 必须 return**：`probe_full_path` 成功但 trace 请求可能失败。之前漏掉 `return None` 导致 `None + ":"` 崩溃。
2. **去尾均值单样本问题**：`sorted_lat[:-1]` 在只有 1 个样本时得空列表 → `sum([])/0` 崩溃。已修复为 ≥3 样本才去尾。
3. **DNS 解析顺序**：腾讯 DoH 是境外服务，国内环境可能超时，阿里 DoH 作为二选，最后才用系统的 dig/nslookup。
4. **阿里云 AK/SK 硬编码**：两个脚本顶部都有明文 AK/SK，注意不要泄露到公开仓库。
5. **Windows curl 路径**：脚本在 `C:\Windows\System32\curl.exe` 等多个位置搜索 curl。

## 修改注意事项

- 改配置常量时，确认两脚本的配置是否需要同步（IP_SET_URLS、POST_URLS 等）
- 改 `_HTTP_FINGERPRINT` 常量会影响所有出站请求的指纹
- 改 `probe_full_path` 时注意测试文件下载的速率检查逻辑（每 50 个 recv 检查一次 `LOWEST_SPEED`）
- 线程安全：`_colo_cache`、`_tested_ips`、`_done_cnt`、`_fail_cnt` 均有独立锁保护
- worker 线程的 `task_done()` 必须在 `finally` 块中调用，否则队列 join 死锁
