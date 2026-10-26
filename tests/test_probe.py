"""Offline regression tests; use the example config and block external connections."""
import importlib.util
import json
import queue
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
config_spec = importlib.util.spec_from_file_location("config", ROOT / "config.example.py")
config = importlib.util.module_from_spec(config_spec)
config_spec.loader.exec_module(config)
spec = importlib.util.spec_from_file_location("probe_under_test", ROOT / "QwenGetBestIPs.py")
probe = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"config": config}):
    spec.loader.exec_module(probe)


def node(ip="104.16.0.1", speed=0, lat=20, colo="HKG", **kwargs):
    return dict(real_ip=ip, target=ip, colo=colo, lat=lat, loss=0,
                tcp_loss=0, tls_loss=0, http_loss=0, score=lat,
                download_speed=speed, **kwargs)


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class FakeSocket:
    """One response per request, with controllable packet fragmentation and timing."""
    def __init__(self, clock, responses):
        self.clock = clock
        self.responses = list(responses)
        self.pending = []
        self.sent = []
        self.closed = False
        self.timeout = 10

    def sendall(self, request):
        if self.pending:
            raise AssertionError("Previous response body was not fully consumed")
        self.sent.append(request)
        self.pending = list(self.responses.pop(0))

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, amount):
        if not self.pending:
            return b""
        delay, chunk = self.pending.pop(0)
        if delay > self.timeout:
            self.clock.now += self.timeout
            raise probe.socket.timeout("read timed out")
        self.clock.now += delay
        if len(chunk) > amount:
            self.pending.insert(0, (0, chunk[amount:]))
        return chunk[:amount]

    def close(self):
        self.closed = True


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(probe, "log").start()
        patch.object(probe.socket, "create_connection", side_effect=AssertionError("External network blocked")).start()
        patch.object(probe, "LOWEST_SPEED", 1000).start()
        probe._early_stop_flag[0] = False
        probe._speed_pass_count[0] = 0
        probe._done_cnt[0] = probe._fail_cnt[0] = 0
        probe._tested_ips.clear()
        probe._colo_cache.clear()

    def test_rank_sorts_results_and_uses_configured_threshold(self):
        results = [node("104.16.0.1", 900), node("104.16.0.2", 1800), node("104.16.0.3", 1200)]
        probe._rank_by_speed(results)
        self.assertEqual([r["download_speed"] for r in results], [1800, 1200, 900])
        self.assertEqual([r["score"] for r in results], [1, 2, 9999])

    def test_untested_nodes_cannot_outrank_speed_passes(self):
        results = [node(lat=0.1), node("104.16.0.2", 1500)]
        probe._rank_by_speed(results)
        self.assertEqual(probe.select_top(results, 1)[0]["real_ip"], "104.16.0.2")

    def test_early_stop_acknowledges_each_queue_item_once(self):
        work = queue.Queue()
        work.put(("104.16.0.1", "source"))
        work.put(None)
        probe._early_stop_flag[0] = True
        thread = threading.Thread(target=probe.worker, args=(work, [], 1, "test-worker"), daemon=True)
        thread.start()
        thread.join(0.5)
        self.assertFalse(thread.is_alive(), "Early stop worker did not exit")
        self.assertEqual(work.unfinished_tasks, 0)

    def test_second_phase_waits_before_speed_sampling(self):
        probe._done_cnt[0] = 200
        patch.object(probe, "CONCURRENCY", 2).start()

        def slow_probe(ip, source):
            time.sleep(0.02)
            return [node(ip)]

        with patch.object(probe, "probe_target_full", side_effect=slow_probe), \
                patch.object(probe, "incremental_batch_speed_test") as sample:
            probe._run_probe_phases([("104.16.0.1", "a"), ("104.16.0.2", "b")], [])
        self.assertEqual(sample.call_count, 1)
        self.assertEqual(len(sample.call_args.args[0]), 2)

    def test_all_failed_samples_are_rejected(self):
        patch.object(probe, "SLEEP_INTERVAL", 0).start()
        patch.object(probe, "PROBE_REPEAT", 1).start()
        patch.object(probe, "ORIGIN_SNI_LIST", ["example.test"]).start()
        failed = dict(success=False, tcp_ms=None, tls_ms=None, ttfb_ms=None, error="TCP")
        with patch.object(probe, "probe_full_path", return_value=failed):
            self.assertIsNone(probe._probe_single_ip("104.16.0.1", "source"))

    def test_http_failure_does_not_count_as_tcp_or_tls_failure(self):
        patch.object(probe, "SLEEP_INTERVAL", 0).start()
        patch.object(probe, "PROBE_REPEAT", 1).start()
        patch.object(probe, "ORIGIN_SNI_LIST", ["one.test", "two.test"]).start()
        good = dict(success=True, tcp_ms=10, tls_ms=20, ttfb_ms=30, total_ms=60, colo="HKG")
        failed = dict(success=False, tcp_ms=10, tls_ms=20, ttfb_ms=None, error="HTTP:500")
        with patch.object(probe, "probe_full_path", side_effect=[good, failed]):
            result = probe._probe_single_ip("104.16.0.1", "source")
        self.assertIsNotNone(result)
        self.assertEqual((result["tcp_loss"], result["tls_loss"], result["http_loss"]), (0, 0, 0.5))
        self.assertEqual(result["lat"], 60)

    def test_empty_ip_sources_are_allowed(self):
        with patch.object(probe, "IP_SET_URLS", []):
            self.assertEqual(probe.fetch_wetest_ips(), [])

    def test_history_normalizes_speed_and_skips_malformed_rows(self):
        payload = [None, "bad", {"ip": "104.16.0.1", "speed_kb_s": "1234.5"},
                   {"ip": "999.1.1.1", "speed_kb_s": 1}, {"ip": "104.16.0.2", "speed_kb_s": None},
                   {"ip": "104.16.0.3", "speed_kb_s": "NaN"}]
        with patch.object(probe, "_http_get", return_value=json.dumps(payload).encode("utf-8")):
            results = probe._fetch_have_post_res("https://source.test")
        self.assertEqual(results, [("104.16.0.1", "https://source.test", 1234.5),
                                   ("104.16.0.2", "https://source.test", 0),
                                   ("104.16.0.3", "https://source.test", 0)])

    def test_speed_sample_is_not_repeated_or_double_counted(self):
        results = [node(speed=1500)]
        probe._speed_pass_count[0] = 1
        sample = dict(success=True, download_speed=1500, ttfb_ms=1, download_cost_time=1)
        with patch.object(probe, "probe_full_path", return_value=sample) as measure:
            probe.incremental_batch_speed_test(results)
            probe.incremental_batch_speed_test(results)
        measure.assert_not_called()
        self.assertEqual(probe._speed_pass_count[0], 1)

    def test_equal_speed_threshold_passes(self):
        sample = dict(success=True, download_speed=1000, ttfb_ms=1, download_cost_time=1)
        with patch.object(probe, "probe_full_path", return_value=sample):
            probe.incremental_batch_speed_test([node()], target_pass_total=1)
        self.assertEqual(probe._speed_pass_count[0], 1)
        self.assertTrue(probe._early_stop_flag[0])

    def fake_connection(self, responses, cached=True):
        clock = Clock()
        sock = FakeSocket(clock, responses)
        patch.object(probe.socket, "create_connection", return_value=sock).start()
        context = Mock()
        context.wrap_socket.return_value = sock
        patch.object(probe, "_ssl_context", return_value=context).start()
        patch.object(probe.time, "perf_counter", side_effect=clock).start()
        if cached:
            probe._colo_cache[("104.16.0.1", "origin.test")] = "HKG"
        return sock, clock

    def test_real_ttfb_and_body_bytes_exclude_headers(self):
        body = b"x" * 5120
        sock, _ = self.fake_connection([[(0.25, b"HTTP/1.1 200 OK\r\nContent-Length: 5120\r\n\r\n"), (1.75, body)]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH, timeout=100)
        self.assertTrue(result["success"], result["error"])
        self.assertEqual(result["ttfb_ms"], 250)
        self.assertEqual(result["download_bytes"], 5120)
        self.assertEqual(result["download_cost_time"], 2000)
        self.assertEqual(result["download_speed"], 2.5)
        self.assertIn(b"Accept-Encoding: identity", sock.sent[0])
        self.assertTrue(sock.closed)

    def test_latency_probe_does_not_download_file(self):
        sock, _ = self.fake_connection([[(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"), (20, b"body")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_TEST_PATH)
        self.assertTrue(result["success"], result["error"])
        self.assertEqual(result["ttfb_ms"], 100)
        self.assertEqual(len(sock.pending), 1)
        self.assertEqual(result["download_bytes"], 0)

    def test_redirect_does_not_count_as_speed_success(self):
        self.fake_connection([[(0.1, b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH)
        self.assertFalse(result["success"])
        self.assertIn("302", result["error"])

    def test_chunked_body_is_decoded_before_counting(self):
        self.fake_connection([[(0.1, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
                               (0.9, b"4\r\ntest\r\n3\r\nabc\r\n0\r\n\r\n")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH)
        self.assertTrue(result["success"], result["error"])
        self.assertEqual(result["download_bytes"], 7)

    def test_fragmented_trace_is_consumed_before_second_request(self):
        trace = b"ip=1.1.1.1\ncolo=HKG\ntls=TLSv1.3\n"
        sock, _ = self.fake_connection([
            [(0.1, f"HTTP/1.1 200 OK\r\nContent-Length: {len(trace)}\r\n\r\n".encode()),
             (0.1, b"ip=1.1.1.1\ncolo="), (0.1, b"HKG\ntls=TLSv1.3\n")],
            [(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")]], cached=False)
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_TEST_PATH)
        self.assertTrue(result["success"], result["error"])
        self.assertEqual(result["colo"], "HKG")
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(probe._colo_cache[("104.16.0.1", "origin.test")], "HKG")

    def test_truncated_body_is_rejected(self):
        self.fake_connection([[(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"), (0.1, b"x")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH)
        self.assertFalse(result["success"])
        self.assertIn("truncated", result["error"])

    def test_speed_deadline_limits_a_blocked_read(self):
        _, clock = self.fake_connection([[(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"),
                                         (0.1, b"x" * 1024), (100, b"x")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH, timeout=100)
        self.assertTrue(result["success"], result["error"])
        self.assertLessEqual(clock.now, 10)
        self.assertEqual(result["download_speed"], 0.1)

    def test_no_body_is_not_a_speed_sample(self):
        self.fake_connection([[(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")]])
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_SPEED_TEST_PATH)
        self.assertFalse(result["success"])

    def test_main_skips_remaining_phase_and_selects_top_n(self):
        history = [(f"104.16.0.{i}", "history", 1500) for i in range(1, 22)]
        patch.object(probe, "TOP_N", 3).start()
        patch.object(probe, "CHANGE_DNS_RESOLVE", True).start()
        patch.object(probe, "ALI_DNS_TARGETS", [{"domain": "example.test"}]).start()
        patch.object(probe, "fetch_have_post_res", return_value=history).start()
        patch.object(probe, "fetch_wetest_ips", return_value=[("104.16.1.1", "third-party")]).start()
        patch.object(probe, "fetch_domains", return_value=[]).start()
        patch.object(probe, "resolve_domains_concurrent", return_value=[]).start()
        post = patch.object(probe, "post_all_results").start()
        update = patch.object(probe, "send_to_aliyunDNS").start()

        def run_phase(items, results, **kwargs):
            results.extend(node(ip, speed=1000 + i) for i, (ip, _) in enumerate(items))

        with patch.object(probe, "_run_probe_phases", side_effect=run_phase) as run, \
                patch.object(probe, "_full_batch_speed_test"):
            probe.main()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(update.call_args.args[0], ["104.16.0.21", "104.16.0.20", "104.16.0.19"])
        post.assert_called_once()

    def test_main_with_no_qualified_results_does_not_update_dns(self):
        patch.object(probe, "CHANGE_DNS_RESOLVE", True).start()
        patch.object(probe, "fetch_have_post_res", return_value=[]).start()
        patch.object(probe, "fetch_wetest_ips", return_value=[]).start()
        patch.object(probe, "fetch_domains", return_value=[]).start()
        patch.object(probe, "resolve_domains_concurrent", return_value=[]).start()
        patch.object(probe, "post_all_results").start()
        update = patch.object(probe, "send_to_aliyunDNS").start()
        probe.main()
        update.assert_not_called()

    def test_worker_errors_do_not_block_the_batch(self):
        with patch.object(probe, "probe_target_full", side_effect=RuntimeError("sample failure")):
            probe._run_probe_phases([("104.16.0.1", "source")], [])
        self.assertEqual(probe._done_cnt[0], 1)
        self.assertEqual(probe._fail_cnt[0], 1)

    def test_cidr_filter_is_stable_and_rejects_invalid_addresses(self):
        patch.object(probe, "_cf_ipv4_cidrs", [probe.ipaddress.IPv4Network("104.16.0.0/13")]).start()
        patch.object(probe.os, "cpu_count", return_value=None).start()
        values = ["104.16.0.2", "999.0.0.1", "104.16.0.1", "104.16.0.2", "8.8.8.8"]
        self.assertEqual(probe.filter_cf_ips(values), ["104.16.0.2", "104.16.0.1"])

    def test_config_rejects_zero_repeats_before_network_access(self):
        with patch.object(probe, "PROBE_REPEAT", 0), self.assertRaises(ValueError):
            probe.main()

    def test_doh_works_without_curl(self):
        payload = {"Answer": [{"type": 1, "data": "104.16.0.1"}, {"type": 1, "data": "198.18.0.1"}]}
        patch.object(probe, "HAS_CURL", False).start()
        with patch.object(probe.urllib.request, "urlopen") as request:
            request.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode("utf-8")
            self.assertEqual(probe._resolve_via_doh("example.test", "https://resolver.test"), ["104.16.0.1"])
        self.assertEqual(request.call_args.args[0].get_header("Accept"), "application/dns-json")

    def test_trace_connection_close_reconnects(self):
        trace = b"colo=HKG\n"
        clock = Clock()
        first = FakeSocket(clock, [[(0.1, b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\n" + trace)]])
        second = FakeSocket(clock, [[(0.1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")]])
        patch.object(probe.socket, "create_connection", side_effect=[first, second]).start()
        context = Mock()
        context.wrap_socket.side_effect = [first, second]
        patch.object(probe, "_ssl_context", return_value=context).start()
        patch.object(probe.time, "perf_counter", side_effect=clock).start()
        result = probe.probe_full_path("104.16.0.1", "origin.test", probe.ORIGIN_TEST_PATH)
        self.assertTrue(result["success"], result["error"])
        self.assertTrue(first.closed and second.closed)

    def test_ssl_handshake_failure_closes_raw_socket(self):
        sock = Mock()
        patch.object(probe.socket, "create_connection", return_value=sock).start()
        context = Mock()
        context.wrap_socket.side_effect = probe.ssl.SSLError("handshake failed")
        patch.object(probe, "_ssl_context", return_value=context).start()
        result = probe.probe_full_path("104.16.0.1", "origin.test")
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["tcp_ms"])
        self.assertIsNone(result["tls_ms"])
        self.assertIn("TLS:", result["error"])
        sock.close.assert_called_once()

    def test_failed_speed_test_is_not_retried_by_full_batch(self):
        results = [node()]
        with patch.object(probe, "probe_full_path", return_value={"success": False}) as sample:
            probe._full_batch_speed_test(results)
            probe._full_batch_speed_test(results)
        sample.assert_called_once()
        self.assertEqual(probe._speed_pass_count[0], 0)

    def test_phase_one_pass_count_contributes_to_early_stop(self):
        probe._speed_pass_count[0] = 19
        with patch.object(probe, "probe_full_path", return_value={"success": True, "download_speed": 1500}) as sample:
            probe.incremental_batch_speed_test([node(), node("104.16.0.2")])
        sample.assert_called_once()
        self.assertEqual(probe._speed_pass_count[0], 20)
        self.assertTrue(probe._early_stop_flag[0])

    def test_disabled_early_stop_ignores_old_flag(self):
        probe._early_stop_flag[0] = True
        with patch.object(probe, "probe_full_path", return_value={"success": True, "download_speed": 1500}) as sample:
            probe.incremental_batch_speed_test([node()], allow_early_stop=False)
        sample.assert_called_once()

    def test_unavailable_domain_source_does_not_exit(self):
        with patch.object(probe, "_http_get", return_value=None):
            self.assertEqual(probe.fetch_domains(max_retry=1), [])


if __name__ == "__main__":
    unittest.main()
