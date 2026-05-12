# Two-Phase Probe with Full Speed Test for Priority IPs

## 背景

当前 `_run_probe_phases` 对所有 IP 统一启用早停机制（`_early_stop_flag`），累计 20 个 IP 测速达标后终止剩余探测。这导致 `HAVE_POST_RES` 中历史高分 IP 可能被提前截断，无法全部完成速度复测。

## 目标

1. 历史测试 speed 达到 `LOWEST_SPEED * 0.5` 的 IP 节点优先探测、全部测速
2. 其余 IP（历史低分 + 无历史记录）延后探测，保留现有早停机制
3. 最终排名统一在两阶段完成后执行

## 设计

### 1. `_run_probe_phases` 增加 `allow_early_stop` 参数

- 新增参数 `allow_early_stop=True`，默认行为不变
- Phase 1 调用时传 `False`：
  - worker 中跳过 `_early_stop_flag` 检查（不提前 continue）
  - 增量测速中 `_early_stop_flag` 不会被设置
- Phase 2 调用时传 `True`：沿用现有早停逻辑

### 2. 新增 `_full_batch_speed_test(results)` 函数

遍历 `results` 中所有 `download_speed == 0` 的 IP，逐个调用 `probe_full_path(..., test_path=ORIGIN_SPEED_TEST_PATH)` 跑速度测试。与 `incremental_batch_speed_test` 的区别：

- **不抽样**：全量遍历，不按区域选 Top
- **不限制区域**：所有 IP 都测
- **不设置早停标志**：纯测速，不触发终止

### 3. `_rank_by_speed` 延迟执行

当前 `_rank_by_speed` 在 `_run_probe_phases` 末尾调用。改为：

- Phase 1 和 Phase 2 的 `_run_probe_phases` 内部不再调用 `_rank_by_speed`
- 两阶段全部完成后在 `main()` 中统一调用一次

### 4. `main()` 流程变更

```
# 改前
拉取数据源 → 合并去重 → _run_probe_phases(全量) → post → 选优 → DNS

# 改后
拉取数据源 →
  Phase 1 IPs: HAVE_POST_RES 中 speed >= LOWEST_SPEED*0.5
  Phase 2 IPs: 其余所有 IP
  Phase 1: _run_probe_phases(priority_ips, allow_early_stop=False)
  Phase 1-speed: _full_batch_speed_test(results)
  Phase 2: _run_probe_phases(remaining_ips, allow_early_stop=True)
_rank_by_speed(results) → post → 选优 → DNS
```

### 涉及文件

- `QwenGetBestIPs.py`：修改 `_run_probe_phases`、`worker`、`main`；新增 `_full_batch_speed_test`
