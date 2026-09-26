import base64
import contextlib
import hashlib
import hmac
import importlib.util
import io
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "production_probe.py"


def load_probe_module():
    spec = importlib.util.spec_from_file_location("production_probe", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def valid_environment(state_path="/tmp/miao-production-probe/state.json"):
    return {
        "MIAO_PRODUCTION_EXPECTED_IPS": "1.1.1.1",
        "MIAO_PROBE_FEISHU_WEBHOOK_URL": (
            "https://open.feishu.cn/open-apis/bot/v2/hook/test-token"
        ),
        "MIAO_PROBE_FEISHU_SECRET": "test-signing-secret",
        "MIAO_PROBE_STATE_PATH": state_path,
    }


class _ReadinessHandler(BaseHTTPRequestHandler):
    server_names = []

    def do_GET(self):  # noqa: N802
        responses = {
            "/readyz": (
                200,
                {"ok": True, "environment": "production", "database": "ok"},
            ),
            "/created": (
                201,
                {"ok": True, "environment": "production", "database": "ok"},
            ),
            "/wrong-environment": (
                200,
                {"ok": True, "environment": "development", "database": "ok"},
            ),
        }
        status, payload = responses.get(self.path, (404, {}))
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_arguments):
        return


class ModulePresenceTests(unittest.TestCase):
    def test_production_probe_module_exists(self):
        self.assertTrue(
            MODULE_PATH.exists(), "production_probe.py has not been implemented"
        )


@unittest.skipUnless(MODULE_PATH.exists(), "production_probe.py is not implemented")
class ProductionProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe_module()
        cls.certificate_directory = tempfile.TemporaryDirectory()
        certificate_root = Path(cls.certificate_directory.name)
        cls.certificate_path = certificate_root / "probe.test.crt"
        cls.private_key_path = certificate_root / "probe.test.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(cls.private_key_path),
                "-out",
                str(cls.certificate_path),
                "-days",
                "1",
                "-subj",
                "/CN=probe.test",
                "-addext",
                "subjectAltName=DNS:probe.test",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _ReadinessHandler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cls.certificate_path, cls.private_key_path)
        server_context.set_servername_callback(
            lambda _socket, server_name, _context: (
                _ReadinessHandler.server_names.append(server_name)
            )
        )
        cls.server.socket = server_context.wrap_socket(
            cls.server.socket, server_side=True
        )
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)
        cls.certificate_directory.cleanup()

    def setUp(self):
        _ReadinessHandler.server_names.clear()

    def test_loads_only_the_fixed_production_target_and_public_expected_ips(self):
        config = self.probe.load_config(valid_environment())

        self.assertEqual(config.url, "https://miao.lvxingzhe.top/readyz")
        self.assertEqual(config.hostname, "miao.lvxingzhe.top")
        self.assertEqual(
            config.expected_ips,
            frozenset({ipaddress.ip_address("1.1.1.1")}),
        )
        self.assertEqual(config.timeout_seconds, 5.0)

    def test_rejects_non_public_ips_missing_signing_and_unapproved_webhooks(self):
        invalid_overrides = [
            {"MIAO_PRODUCTION_EXPECTED_IPS": value}
            for value in (
                "127.0.0.1",
                "10.0.0.1",
                "100.64.0.1",
                "203.0.113.8",
                "224.0.0.1",
                "fc00::1",
                "ff02::1",
            )
        ]
        invalid_overrides.extend([
            {"MIAO_PROBE_FEISHU_SECRET": ""},
            {"MIAO_PROBE_FEISHU_WEBHOOK_URL": "https://example.com/hook"},
            {
                "MIAO_PROBE_FEISHU_WEBHOOK_URL": (
                    "https://open.larkoffice.com.example.com/"
                    "open-apis/bot/v2/hook/test-token"
                )
            },
        ])

        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                environment = valid_environment()
                environment.update(overrides)
                with self.assertRaises(self.probe.ConfigError):
                    self.probe.load_config(environment)

    def test_accepts_both_official_feishu_webhook_hosts(self):
        for hostname in ("open.feishu.cn", "open.larkoffice.com"):
            with self.subTest(hostname=hostname):
                environment = valid_environment()
                environment["MIAO_PROBE_FEISHU_WEBHOOK_URL"] = (
                    f"https://{hostname}/open-apis/bot/v2/hook/test-token"
                )

                config = self.probe.load_config(environment)

                self.assertEqual(
                    config.feishu_webhook_url,
                    environment["MIAO_PROBE_FEISHU_WEBHOOK_URL"],
                )

    def test_configuration_error_log_reports_only_a_safe_category(self):
        environment = valid_environment()
        secret_value = environment["MIAO_PROBE_FEISHU_SECRET"]
        environment["MIAO_PROBE_FEISHU_WEBHOOK_URL"] = "https://example.com/private"
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = self.probe.main(environment)

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["result"], "configuration_error")
        self.assertEqual(payload["category"], "Feishu webhook URL is not an approved endpoint")
        self.assertNotIn("example.com", output.getvalue())
        self.assertNotIn(secret_value, output.getvalue())

    def test_requires_every_dns_answer_to_match_the_server_ip_allowlist(self):
        expected = frozenset({
            ipaddress.ip_address("1.1.1.1"),
            ipaddress.ip_address("2606:4700:4700::1111"),
        })

        healthy, addresses = self.probe.verify_dns_resolution(
            "miao.lvxingzhe.top",
            expected,
            resolver=lambda _hostname: {"1.1.1.1", "2606:4700:4700::1111"},
        )
        mismatch, _ = self.probe.verify_dns_resolution(
            "miao.lvxingzhe.top",
            expected,
            resolver=lambda _hostname: {"1.1.1.1", "8.8.8.8"},
        )
        empty, _ = self.probe.verify_dns_resolution(
            "miao.lvxingzhe.top", expected, resolver=lambda _hostname: set()
        )

        self.assertEqual(healthy, self.probe.CheckResult(True, "ok"))
        self.assertEqual(addresses, expected)
        self.assertEqual(mismatch.category, "dns_mismatch")
        self.assertEqual(empty.category, "dns_empty")

    def test_https_connects_to_the_verified_ip_but_keeps_hostname_tls_and_sni(self):
        trusted_context = ssl.create_default_context(cafile=str(self.certificate_path))
        addresses = frozenset({ipaddress.ip_address("127.0.0.1")})
        port = self.server.server_port

        result = self.probe.perform_health_check(
            f"https://probe.test:{port}/readyz",
            addresses,
            timeout_seconds=1,
            ssl_context=trusted_context,
        )
        wrong_hostname = self.probe.perform_health_check(
            f"https://wrong.test:{port}/readyz",
            addresses,
            timeout_seconds=1,
            ssl_context=trusted_context,
        )
        untrusted = self.probe.perform_health_check(
            f"https://probe.test:{port}/readyz",
            addresses,
            timeout_seconds=1,
        )

        self.assertEqual(result, self.probe.CheckResult(True, "ok"))
        self.assertEqual(wrong_hostname.category, "tls_error")
        self.assertEqual(untrusted.category, "tls_error")
        self.assertEqual(_ReadinessHandler.server_names[:2], ["probe.test", "wrong.test"])

    def test_rejects_non_200_and_environment_contract_drift(self):
        trusted_context = ssl.create_default_context(cafile=str(self.certificate_path))
        addresses = frozenset({ipaddress.ip_address("127.0.0.1")})
        base_url = f"https://probe.test:{self.server.server_port}"

        created = self.probe.perform_health_check(
            f"{base_url}/created", addresses, 1, ssl_context=trusted_context
        )
        wrong_environment = self.probe.perform_health_check(
            f"{base_url}/wrong-environment",
            addresses,
            1,
            ssl_context=trusted_context,
        )

        self.assertEqual(created.category, "http_201")
        self.assertEqual(wrong_environment.category, "environment_mismatch")

    def test_probe_reuses_the_single_verified_dns_result_for_https(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.probe.load_config(
                valid_environment(str(Path(directory) / "state.json"))
            )
            calls = []

            def health_checker(url, addresses, timeout_seconds):
                calls.append((url, addresses, timeout_seconds))
                return self.probe.CheckResult(True, "ok")

            result = self.probe.probe_target(
                config,
                resolver=lambda _hostname: {"1.1.1.1"},
                health_checker=health_checker,
            )

        self.assertEqual(result, self.probe.CheckResult(True, "ok"))
        self.assertEqual(calls[0][1], config.expected_ips)

    def test_state_requires_two_failures_and_two_successes_per_incident(self):
        state = self.probe.ProbeState()
        started_at = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

        state = self.probe.record_result(
            state,
            self.probe.CheckResult(False, "dns_mismatch"),
            started_at,
            incident_id_factory=lambda: "incident-one",
        )
        state = self.probe.record_result(
            state,
            self.probe.CheckResult(False, "dns_mismatch"),
            started_at + timedelta(seconds=10),
            incident_id_factory=lambda: "incident-one",
        )

        self.assertEqual(state.status, "firing")
        self.assertEqual(state.incident_id, "incident-one")
        self.assertEqual([item.event_type for item in state.outbox], ["firing"])

        state = self.probe.record_result(
            state,
            self.probe.CheckResult(True, "ok"),
            started_at + timedelta(minutes=5),
        )
        state = self.probe.record_result(
            state,
            self.probe.CheckResult(True, "ok"),
            started_at + timedelta(minutes=5, seconds=10),
        )

        self.assertEqual(state.status, "normal")
        self.assertIsNone(state.incident_id)
        self.assertEqual(
            [item.event_type for item in state.outbox], ["firing", "recovered"]
        )

    def test_intervening_results_reset_failure_and_recovery_counters(self):
        state = self.probe.ProbeState()
        now = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)
        for offset, result in enumerate((False, True, False)):
            state = self.probe.record_result(
                state,
                self.probe.CheckResult(result, "ok" if result else "timeout"),
                now + timedelta(seconds=offset),
                incident_id_factory=lambda: "must-not-fire",
            )
        self.assertEqual(state.status, "normal")
        self.assertEqual(state.consecutive_failures, 1)

    def test_state_file_round_trips_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state = self.probe.ProbeState(
                status="firing",
                consecutive_failures=2,
                incident_id="incident-persisted",
                first_failure_at="2026-09-26T12:00:00.000000Z",
            )
            self.probe.save_state(state_path, state)

            restored = self.probe.load_state(state_path)
            self.assertEqual(restored.incident_id, "incident-persisted")

            state_path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(self.probe.StateError):
                self.probe.load_state(state_path)

    def test_feishu_payload_uses_official_signature_without_leaking_secret(self):
        notification = self.probe.Notification(
            event_type="firing",
            incident_id="incident-123",
            failure_category="dns_mismatch",
            first_failure_at="2026-09-26T12:00:00Z",
            checked_at="2026-09-26T12:00:10Z",
        )

        payload = self.probe.build_feishu_payload(
            notification, "secret", timestamp=123
        )
        expected = base64.b64encode(
            hmac.new(
                b"123\nsecret", digestmod=hashlib.sha256
            ).digest()
        ).decode("ascii")

        self.assertEqual(payload["sign"], expected)
        self.assertNotIn("secret", json.dumps(payload))
        self.assertIn("production", payload["content"]["text"])

    def test_delivery_keeps_failed_outbox_event_and_removes_success(self):
        notification = self.probe.Notification(
            event_type="firing",
            incident_id="incident-123",
            failure_category="timeout",
            first_failure_at="2026-09-26T12:00:00Z",
            checked_at="2026-09-26T12:00:10Z",
        )
        failed_state = self.probe.ProbeState(outbox=[notification])

        with self.assertRaises(self.probe.DeliveryError):
            self.probe.deliver_pending(
                failed_state,
                lambda _notification: (_ for _ in ()).throw(
                    self.probe.DeliveryError("timeout")
                ),
            )
        self.assertEqual(len(failed_state.outbox), 1)

        self.probe.deliver_pending(failed_state, lambda _notification: None)
        self.assertEqual(failed_state.outbox, [])

    def test_cycle_persists_an_alert_before_delivery_and_retries_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            config = self.probe.load_config(valid_environment(str(state_path)))
            first_at = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

            first_exit = self.probe.run_cycle(
                config,
                checked_at=first_at,
                probe=lambda _config: self.probe.CheckResult(False, "timeout"),
                sender=lambda _notification: None,
            )

            def failed_sender(_notification):
                raise self.probe.DeliveryError("timeout")

            second_exit = self.probe.run_cycle(
                config,
                checked_at=first_at + timedelta(seconds=10),
                probe=lambda _config: self.probe.CheckResult(False, "timeout"),
                sender=failed_sender,
            )
            persisted = self.probe.load_state(state_path)
            delivered = []
            retry_exit = self.probe.run_cycle(
                config,
                checked_at=first_at + timedelta(minutes=5),
                probe=lambda _config: self.probe.CheckResult(False, "timeout"),
                sender=delivered.append,
            )

            self.assertEqual(first_exit, 1)
            self.assertEqual(second_exit, 1)
            self.assertEqual(len(persisted.outbox), 1)
            self.assertEqual(retry_exit, 1)
            self.assertEqual(len(delivered), 1)
            self.assertEqual(self.probe.load_state(state_path).outbox, [])


class WorkflowAssetTests(unittest.TestCase):
    def test_workflow_is_production_only_scheduled_manual_and_stateful(self):
        workflow_path = REPO_ROOT / ".github/workflows/production-probe.yml"
        if not workflow_path.exists():
            self.fail("production GitHub Actions workflow has not been implemented")
        workflow = workflow_path.read_text(encoding="utf-8")

        for required in (
            "schedule:",
            "cron: '*/5 * * * *'",
            "workflow_dispatch:",
            "cancel-in-progress: false",
            "permissions:\n  contents: read",
            "MIAO_PRODUCTION_EXPECTED_IPS",
            "secrets.MIAO_PRODUCTION_EXPECTED_IPS",
            "secrets.MIAO_PROBE_FEISHU_WEBHOOK_URL",
            "secrets.MIAO_PROBE_FEISHU_SECRET",
            "actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25",
            "actions/cache/save@caa296126883cff596d87d8935842f9db880ef25",
            "continue-on-error: true",
            "if: always()",
        ):
            self.assertIn(required, workflow)
        self.assertEqual(workflow.count("python3 production_probe.py"), 2)
        self.assertNotIn("development", workflow.lower())

    def test_readme_documents_only_github_configuration_and_acceptance(self):
        readme_path = REPO_ROOT / "README.md"
        if not readme_path.exists():
            self.fail("README.md has not been implemented")
        readme = readme_path.read_text(encoding="utf-8")

        for required in (
            "MIAO_PRODUCTION_EXPECTED_IPS",
            "MIAO_PROBE_FEISHU_WEBHOOK_URL",
            "MIAO_PROBE_FEISHU_SECRET",
            "116.205.225.8",
            "workflow_dispatch",
            "dns_mismatch",
            "公开仓库",
            "约 5 分钟",
        ):
            self.assertIn(required, readme)
        self.assertIn("不需要独立 Linux 探测机", readme)
        self.assertNotIn("systemd", readme)


if __name__ == "__main__":
    unittest.main()
