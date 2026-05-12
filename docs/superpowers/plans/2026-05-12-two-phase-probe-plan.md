# Two-Phase Probe with Priority IP Speed Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 历史高分 IP（speed >= 0.5 * LOWEST_SPEED）优先全量探测 + 全量测速，其余 IP 延后探测且保留早停机制。

**Architecture:** 单文件改动，`_run_probe_phases` 增加 `allow_early_stop` 参数控制早停行为，新增 `_full_batch_speed_test` 函数对 Phase 1 结果全量测速，`main()` 拆分为两阶段。

**Tech Stack:** Python 3.8+, threading, queue, 无外部依赖

---

## File Structure

| 文件 | 改动类型 | 职责 |
|------|---------|------|
| `QwenGetBestIPs.py:829-873` | Modify | `worker()`: 新增 `allow_early_stop` 参数，控制是否跳过早停检查 |
| `QwenGetBestIPs.py:983-1044` | Modify | `incremental_batch_speed_test()`: 新增 `allow_early_stop` 参数，控制是否设置早停标志 |
| `QwenGetBestIPs.py:1071-1136` | Modify | `_run_probe_phases()`: 新增 `allow_early_stop` 参数，移除 `_rank_by_speed` 调用 |
| `QwenGetBestIPs.py:1044 之后` | Create | 新增 `_full_batch_speed_test()` 函数 |
| `QwenGetBestIPs.py:1138-1223` | Modify | `main()`: 拆分 Phase 1 / Phase 2，插入 `_full_batch_speed_test`，统一调用 `_rank_by_speed` |

---

### Task 1: `worker()` 增加 `allow_early_stop` 参数

**Files:**
- Modify: `QwenGetBestIPs.py:829-873`

- [ ] **Step 1: 修改 worker 函数签名和早停检查逻辑**

当前 `worker` 在第 843-845 行无条件检查 `_early_stop_flag[0]`，当 `allow_early_stop=False` 时应跳过。

```python
# 修改 worker 签名，增加 allow_early_stop 参数
def worker(q, results, total, worker_name, allow_early_stop=True):
    """工作线程：从队列取任务探测，保证 task_done() 必定被调用"""
    threading.current_thread().name = worker_name   # 显式命名
    while True:
        d = None
        try:
            d = q.get()
            if d is None:
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
            log("ERROR", f" worker crashed: {type(e).__name__}: {e}")
        finally:
            if d is not None:
                q.task_done()
```

- [ ] **Step 2: 确认语法正确，不运行测试（网络探测脚本无法本地单元测试）**

Run: `python -c "import py_compile; py_compile.compile('QwenGetBestIPs.py', doraise=True)"`
Expected: 无输出（编译通过）

- [ ] **Step 3: Commit**

```bash
git add QwenGetBestIPs.py
git commit -m "refactor: worker() add allow_early_stop param to skip early stop check"
```

---

### Task 2: `incremental_batch_speed_test()` 增加 `allow_early_stop` 参数

**Files:**
- Modify: `QwenGetBestIPs.py:983-1044`

- [ ] **Step 1: 修改函数签名和早停相关逻辑**

两处改动：
1. 函数开头的早停检查（原 991-992 行）：仅当 `allow_early_stop=True` 时才 return
2. 函数末尾设置早停标志（原 1040-1042 行）：仅当 `allow_early_stop=True` 时才设置

```python
def incremental_batch_speed_test(results, batch_size=100, target_pass_total=20, allow_early_stop=True):
    """
    增量批次测速：每完成 batch_size 个 IP 延迟测试后，从已完成的结果中选取三区域各 Top5 进行测速。
    当全局速度达标数达到 target_pass_total 时设置提前终止标志（仅 allow_early_stop=True 时）。
    返回本轮新增的达标数量。
    """
    if allow_early_stop and _early_stop_flag[0]:
        return 0

    with _batch_lock:
        # ... (中间代码不变：选取三区域 Top5、去重、测速) ...

        # 检查是否已达到总目标（仅 allow_early_stop=True 时设置早停标志）
        if allow_early_stop and _speed_pass_count[0] >= target_pass_total:
            _early_stop_flag[0] = True
            log("INFO", f"=== Early stop triggered: {_speed_pass_count[0]} IPs passed speed test ===")

        return local_pass
```

- [ ] **Step 2: 验证编译**

Run: `python -c "import py_compile; py_compile.compile('QwenGetBestIPs.py', doraise=True)"`
Expected: 无输出

- [ ] **Step 3: Commit**

```bash
git add QwenGetBestIPs.py
git commit -m "refactor: incremental_batch_speed_test() add allow_early_stop param"
```

---

### Task 3: `_run_probe_phases()` 增加 `allow_early_stop` 参数，移除 `_rank_by_speed` 调用

**Files:**
- Modify: `QwenGetBestIPs.py:1071-1136`

- [ ] **Step 1: 修改函数签名，传递参数给 worker 和 incremental_batch_speed_test**

改动点：
1. 函数签名增加 `allow_early_stop=True`
2. 创建 worker 线程时传递 `allow_early_stop`（args 元组末尾增加）
3. 早停检查 `if _early_stop_flag[0]`（1104-1106 行和 1117 行）仅在 `allow_early_stop=True` 时生效
4. 调用 `incremental_batch_speed_test` 时传递 `allow_early_stop`
5. **移除末尾 `_rank_by_speed(results)` 调用**（1135-1136 行）

```python
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

    batch_size = 100
    idx = 0
    last_batch_done = 0

    while idx < total:
        if allow_early_stop and _early_stop_flag[0]:
            log("INFO", "Early stop detected, stopping probe...")
            break

        batch_end = min(idx + batch_size, total)
        for i in range(idx, batch_end):
            q.put(ip_source_list[i])

        idx = batch_end

        expected_done = batch_end
        while _done_cnt[0] < expected_done and (not allow_early_stop or not _early_stop_flag[0]):
            time.sleep(0.1)

        if _done_cnt[0] > last_batch_done and len(results) > 0:
            incremental_batch_speed_test(results, batch_size=batch_size, target_pass_total=20,
                                         allow_early_stop=allow_early_stop)
            last_batch_done = _done_cnt[0]

    q.join()
    log("INFO", "==== Probing DONE ====")

    for _ in ts:
        q.put(None)
    for t in ts:
        t.join()

    # _rank_by_speed 已移至 main() 统一调用
```

- [ ] **Step 2: 验证编译**

Run: `python -c "import py_compile; py_compile.compile('QwenGetBestIPs.py', doraise=True)"`
Expected: 无输出

- [ ] **Step 3: Commit**

```bash
git add QwenGetBestIPs.py
git commit -m "refactor: _run_probe_phases() add allow_early_stop param, remove _rank_by_speed call"
```

---

### Task 4: 新增 `_full_batch_speed_test()` 函数

**Files:**
- Create: `QwenGetBestIPs.py` 在 `_rank_by_speed`（1047 行）之前插入新函数

- [ ] **Step 1: 编写新函数**

在 `incremental_batch_speed_test` 函数之后、`_rank_by_speed` 之前插入：

```python
def _full_batch_speed_test(results):
    """
    全量速度复测：遍历 results 中所有未测速的 IP，逐个跑 ORIGIN_SPEED_TEST_PATH 速度测试。
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
```

- [ ] **Step 2: 验证编译**

Run: `python -c "import py_compile; py_compile.compile('QwenGetBestIPs.py', doraise=True)"`
Expected: 无输出

- [ ] **Step 3: Commit**

```bash
git add QwenGetBestIPs.py
git commit -m "feat: add _full_batch_speed_test() for full speed test on all results"
```

---

### Task 5: `main()` 拆分两阶段 + 统一 `_rank_by_speed`

**Files:**
- Modify: `QwenGetBestIPs.py:1138-1223`（原 main 函数）

- [ ] **Step 1: 修改 IP 分组逻辑和探测流程**

当前 main 在去重后直接调用 `_run_probe_phases(all_ip_sources, results)`。改为：
1. 从 `have_post_res_list` 中提取 speed >= `LOWEST_SPEED * 0.5` 的 IP 作为 priority_ips
2. 其余 IP 归入 remaining_ips
3. Phase 1: 探测 priority_ips（allow_early_stop=False）→ 全量测速
4. Phase 2: 探测 remaining_ips（allow_early_stop=True）
5. 两阶段完成后统一 `_rank_by_speed(results)`

```python
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
    for ip, url, speed in have_post_res_list:
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
        top_n_res = (
            top_region(speed_confirmed, colo="HKG", topN=8) +
            top_region(speed_confirmed, region="NorthAmerica", topN=8) +
            top_region(speed_confirmed, region="EastAsia", topN=8)
        )
        top_n_res = select_top(top_n_res, 10)
    else:
        log("WARN", "No IPs have completed speed test, falling back to all results")
        top_n_res = (
            top_region(results, colo="HKG", topN=8) +
            top_region(results, region="NorthAmerica", topN=8) +
            top_region(results, region="EastAsia", topN=8)
        )
        top_n_res = select_top(top_n_res, 10)

    print_top_results(top_n_res)

    # 更改 aliyun DNS
    if CHANGE_DNS_RESOLVE:
        for cfg in ALI_DNS_TARGETS:
            send_to_aliyunDNS([r["real_ip"] for r in top_n_res], cfg["domain"])
```

- [ ] **Step 2: 验证编译**

Run: `python -c "import py_compile; py_compile.compile('QwenGetBestIPs.py', doraise=True)"`
Expected: 无输出

- [ ] **Step 3: Commit**

```bash
git add QwenGetBestIPs.py
git commit -m "feat: split main() into two-phase probe with priority IP full speed test"
```

---

## Self-Review

**1. Spec coverage:**
| Spec 需求 | Task |
|-----------|------|
| `_run_probe_phases` 增加 `allow_early_stop` 参数 | Task 3 |
| Phase 1 调用时传 `False`，worker 跳过早停检查 | Task 1 + Task 3 |
| Phase 1 调用时传 `False`，增量测速不设置早停标志 | Task 2 + Task 3 |
| Phase 2 调用时传 `True`，沿用现有早停逻辑 | Task 3（默认值 True） |
| 新增 `_full_batch_speed_test(results)` 全量测速 | Task 4 |
| 不抽样、不限制区域、不设置早停标志 | Task 4 |
| `_rank_by_speed` 延迟到两阶段后统一执行 | Task 3 移除 + Task 5 统一调用 |
| main() Phase 1 选 speed >= LOWEST_SPEED*0.5 的 IP | Task 5 |
| Phase 1 → 探测 → 全量测速 → Phase 2 → 排名 | Task 5 |

**2. Placeholder scan:** 无 TBD/TODO，所有步骤包含完整代码。

**3. Type consistency:** 
- `worker` 新增参数位置在 args 末尾，`_run_probe_phases` 传递时对应
- `incremental_batch_speed_test` 新增 `allow_early_stop=True`，`_run_probe_phases` 传参匹配
- `_full_batch_speed_test` 直接操作 `results` 列表元素（in-place 修改 `download_speed`），与 `incremental_batch_speed_test` 一致
- `_rank_by_speed` 从 Task 3 移除，Task 5 统一调用，无重复执行风险
