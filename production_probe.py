#!/usr/bin/env python3
"""GitHub-hosted public readiness probe for the Miao production service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, FrozenSet, Iterable, Iterator, Mapping, Optional, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Resolver = Callable[[str], Iterable[str]]

TARGET_URL = "https://miao.lvxingzhe.top/readyz"
TARGET_HOSTNAME = "miao.lvxingzhe.top"
MAX_RESPONSE_BYTES = 65_536
USER_AGENT = "miao-github-production-probe/1"


class ConfigError(ValueError):
    """Raised when the GitHub Actions configuration is missing or unsafe."""


class StateError(RuntimeError):
    """Raised instead of silently discarding a corrupt cached incident state."""


class DeliveryError(RuntimeError):
    """A redacted Feishu delivery failure category."""


class _ProbeTimeout(RuntimeError):
    pass


@dataclass(frozen=True)
class ProbeConfig:
    url: str
    hostname: str
    expected_ips: FrozenSet[IpAddress]
    feishu_webhook_url: str
    feishu_secret: str
    state_path: Path
    timeout_seconds: float = 5.0


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    category: str


@dataclass(frozen=True)
class Notification:
    event_type: str
    incident_id: str
    failure_category: str
    first_failure_at: str
    checked_at: str


@dataclass
class ProbeState:
    status: str = "normal"
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    incident_id: Optional[str] = None
    first_failure_at: Optional[str] = None
    last_failure_category: Optional[str] = None
    last_checked_at: Optional[str] = None
    outbox: list[Notification] = field(default_factory=list)


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise ConfigError("missing required probe configuration")
    return value


def _parse_expected_ips(raw_value: str) -> FrozenSet[IpAddress]:
    values = [value.strip() for value in raw_value.split(",") if value.strip()]
    if not values:
        raise ConfigError("at least one expected production server IP is required")
    try:
        addresses = frozenset(ipaddress.ip_address(value) for value in values)
    except ValueError as error:
        raise ConfigError("expected production server IP list is invalid") from error
    if any(not address.is_global or address.is_multicast for address in addresses):
        raise ConfigError("expected production server IP list contains a non-public IP")
    return addresses


def _validate_feishu_webhook(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ConfigError("Feishu webhook URL is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "open.feishu.cn"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or re.fullmatch(r"/open-apis/bot/v2/hook/[A-Za-z0-9_-]+", parsed.path)
        is None
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError("Feishu webhook URL is not an approved endpoint")


def load_config(environment: Optional[Mapping[str, str]] = None) -> ProbeConfig:
    values = os.environ if environment is None else environment
    webhook_url = _required(values, "MIAO_PROBE_FEISHU_WEBHOOK_URL")
    _validate_feishu_webhook(webhook_url)
    state_path = Path(_required(values, "MIAO_PROBE_STATE_PATH"))
    if not state_path.is_absolute():
        raise ConfigError("probe state path must be absolute")
    return ProbeConfig(
        url=TARGET_URL,
        hostname=TARGET_HOSTNAME,
        expected_ips=_parse_expected_ips(
            _required(values, "MIAO_PRODUCTION_EXPECTED_IPS")
        ),
        feishu_webhook_url=webhook_url,
        feishu_secret=_required(values, "MIAO_PROBE_FEISHU_SECRET"),
        state_path=state_path,
    )


def resolve_addresses(hostname: str) -> set[str]:
    answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    return {answer[4][0] for answer in answers}


def verify_dns_resolution(
    hostname: str,
    expected_ips: FrozenSet[IpAddress],
    resolver: Resolver = resolve_addresses,
) -> tuple[CheckResult, FrozenSet[IpAddress]]:
    try:
        resolved_ips = frozenset(
            ipaddress.ip_address(value) for value in resolver(hostname)
        )
    except (OSError, ValueError):
        return CheckResult(False, "dns_error"), frozenset()
    if not resolved_ips:
        return CheckResult(False, "dns_empty"), resolved_ips
    if not resolved_ips.issubset(expected_ips):
        return CheckResult(False, "dns_mismatch"), resolved_ips
    return CheckResult(True, "ok"), resolved_ips


def _network_category(error: BaseException) -> str:
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, (ssl.SSLError, ssl.CertificateError)):
        return "tls_error"
    if isinstance(error, socket.gaierror):
        return "dns_error"
    if isinstance(error, (ConnectionError, OSError)):
        return "connection_error"
    return "network_error"


def _read_bounded_response(response: http.client.HTTPResponse) -> bytes:
    expected_length = response.length
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if expected_length is not None and len(body) < min(
        expected_length, MAX_RESPONSE_BYTES + 1
    ):
        raise http.client.IncompleteRead(body, expected_length - len(body))
    return body


def _read_pinned_https(
    url: str,
    connect_addresses: FrozenSet[IpAddress],
    timeout_seconds: float,
    ssl_context: Optional[ssl.SSLContext],
) -> tuple[int, bytes]:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if parsed.scheme != "https" or hostname is None:
        raise ValueError("readiness target must be HTTPS with a hostname")
    port = parsed.port or 443
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    context = ssl.create_default_context() if ssl_context is None else ssl_context
    started_at = time.monotonic()
    last_error: Optional[BaseException] = None

    for address in sorted(connect_addresses, key=lambda item: (item.version, int(item))):
        remaining = timeout_seconds - (time.monotonic() - started_at)
        if remaining <= 0:
            raise socket.timeout("HTTPS deadline reached")
        connection = http.client.HTTPSConnection(
            hostname, port=port, timeout=remaining, context=context
        )
        raw_socket: Optional[socket.socket] = None
        try:
            raw_socket = socket.create_connection((str(address), port), remaining)
            connection.sock = context.wrap_socket(raw_socket, server_hostname=hostname)
            raw_socket = None
            connection.request(
                "GET",
                request_target,
                headers={"User-Agent": USER_AGENT, "Connection": "close"},
            )
            response = connection.getresponse()
            return response.status, _read_bounded_response(response)
        except (OSError, ssl.SSLError) as error:
            last_error = error
        finally:
            if raw_socket is not None:
                raw_socket.close()
            connection.close()

    if last_error is not None:
        raise last_error
    raise OSError("no verified HTTPS address is available")


def perform_health_check(
    url: str,
    connect_addresses: FrozenSet[IpAddress],
    timeout_seconds: float,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> CheckResult:
    try:
        status, body = _read_pinned_https(
            url, connect_addresses, timeout_seconds, ssl_context
        )
    except (OSError, ssl.SSLError) as error:
        return CheckResult(False, _network_category(error))
    except http.client.HTTPException:
        return CheckResult(False, "invalid_http_response")
    except ValueError:
        return CheckResult(False, "network_error")

    if status != 200:
        category = "redirect" if 300 <= status < 400 else f"http_{status}"
        return CheckResult(False, category)
    if len(body) > MAX_RESPONSE_BYTES:
        return CheckResult(False, "response_too_large")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return CheckResult(False, "invalid_json")
    if not isinstance(payload, dict):
        return CheckResult(False, "contract_error")
    if payload.get("environment") != "production":
        return CheckResult(False, "environment_mismatch")
    if payload.get("ok") is not True or payload.get("database") != "ok":
        return CheckResult(False, "contract_error")
    return CheckResult(True, "ok")


@contextmanager
def _total_timeout(seconds: float) -> Iterator[None]:
    if (
        not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def raise_timeout(_signum, _frame):
        raise _ProbeTimeout("probe deadline reached")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, raise_timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def probe_target(
    config: ProbeConfig,
    resolver: Resolver = resolve_addresses,
    health_checker: Callable[[str, FrozenSet[IpAddress], float], CheckResult] = (
        perform_health_check
    ),
) -> CheckResult:
    started_at = time.monotonic()
    try:
        with _total_timeout(config.timeout_seconds):
            dns_result, resolved_ips = verify_dns_resolution(
                config.hostname, config.expected_ips, resolver
            )
            if not dns_result.ok:
                return dns_result
            remaining = config.timeout_seconds - (time.monotonic() - started_at)
            if remaining <= 0:
                return CheckResult(False, "timeout")
            return health_checker(config.url, resolved_ips, remaining)
    except _ProbeTimeout:
        return CheckResult(False, "timeout")


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def record_result(
    state: ProbeState,
    result: CheckResult,
    checked_at: datetime,
    incident_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    failure_threshold: int = 2,
    recovery_threshold: int = 2,
) -> ProbeState:
    checked_at_iso = _iso(checked_at)
    state.last_checked_at = checked_at_iso

    if state.status == "normal":
        if result.ok:
            state.consecutive_failures = 0
            state.consecutive_successes = 0
            state.first_failure_at = None
            state.last_failure_category = None
        else:
            state.consecutive_failures += 1
            state.consecutive_successes = 0
            state.first_failure_at = state.first_failure_at or checked_at_iso
            state.last_failure_category = result.category
            if state.consecutive_failures >= failure_threshold:
                state.status = "firing"
                state.incident_id = incident_id_factory()
                state.outbox.append(Notification(
                    event_type="firing",
                    incident_id=state.incident_id,
                    failure_category=result.category,
                    first_failure_at=state.first_failure_at,
                    checked_at=checked_at_iso,
                ))
    elif result.ok:
        state.consecutive_failures = 0
        state.consecutive_successes += 1
        if state.consecutive_successes >= recovery_threshold:
            if not state.incident_id or not state.first_failure_at:
                raise StateError("firing state is incomplete")
            state.outbox.append(Notification(
                event_type="recovered",
                incident_id=state.incident_id,
                failure_category=state.last_failure_category or "unknown",
                first_failure_at=state.first_failure_at,
                checked_at=checked_at_iso,
            ))
            state.status = "normal"
            state.consecutive_successes = 0
            state.incident_id = None
            state.first_failure_at = None
            state.last_failure_category = None
    else:
        state.consecutive_failures = min(
            failure_threshold, state.consecutive_failures + 1
        )
        state.consecutive_successes = 0
        state.last_failure_category = result.category
    return state


def _state_payload(state: ProbeState) -> dict:
    return {
        "version": 1,
        "status": state.status,
        "consecutive_failures": state.consecutive_failures,
        "consecutive_successes": state.consecutive_successes,
        "incident_id": state.incident_id,
        "first_failure_at": state.first_failure_at,
        "last_failure_category": state.last_failure_category,
        "last_checked_at": state.last_checked_at,
        "outbox": [asdict(notification) for notification in state.outbox],
    }


def save_state(path: Path, state: ProbeState) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(
        json.dumps(_state_payload(state), separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)


def load_state(path: Path) -> ProbeState:
    if not path.exists():
        return ProbeState()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("unsupported state")
        status = payload["status"]
        if status not in {"normal", "firing"}:
            raise ValueError("invalid status")
        outbox_payload = payload.get("outbox", [])
        if not isinstance(outbox_payload, list):
            raise ValueError("invalid outbox")
        state = ProbeState(
            status=status,
            consecutive_failures=int(payload["consecutive_failures"]),
            consecutive_successes=int(payload["consecutive_successes"]),
            incident_id=payload.get("incident_id"),
            first_failure_at=payload.get("first_failure_at"),
            last_failure_category=payload.get("last_failure_category"),
            last_checked_at=payload.get("last_checked_at"),
            outbox=[Notification(**item) for item in outbox_payload],
        )
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        raise StateError("cached probe state is invalid") from error
    if state.consecutive_failures < 0 or state.consecutive_successes < 0:
        raise StateError("cached probe state counters are invalid")
    if state.status == "firing" and (
        not state.incident_id or not state.first_failure_at
    ):
        raise StateError("cached firing state is incomplete")
    return state


def build_feishu_payload(
    notification: Notification,
    signing_secret: str,
    timestamp: Optional[int] = None,
) -> dict:
    seconds = int(time.time()) if timestamp is None else timestamp
    string_to_sign = f"{seconds}\n{signing_secret}".encode("utf-8")
    signature = hmac.new(string_to_sign, digestmod=hashlib.sha256).digest()
    state_label = "触发" if notification.event_type == "firing" else "恢复"
    text = "\n".join([
        "Miao 生产公网可用性告警",
        "环境: production",
        f"状态: {state_label}",
        f"失败类别: {notification.failure_category}",
        f"首次失败: {notification.first_failure_at}",
        f"最近检查: {notification.checked_at}",
        f"incident ID: {notification.incident_id}",
    ])
    return {
        "timestamp": str(seconds),
        "sign": base64.b64encode(signature).decode("ascii"),
        "msg_type": "text",
        "content": {"text": text},
    }


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_feishu(config: ProbeConfig, notification: Notification) -> None:
    body = json.dumps(
        build_feishu_payload(notification, config.feishu_secret),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        config.feishu_webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        },
    )
    opener = build_opener(ProxyHandler({}), _RejectRedirects())
    try:
        with _total_timeout(config.timeout_seconds):
            with opener.open(request, timeout=config.timeout_seconds) as response:
                status = response.status
                response_body = _read_bounded_response(response)
    except _ProbeTimeout:
        raise DeliveryError("timeout") from None
    except HTTPError as error:
        category = "redirect" if 300 <= error.code < 400 else f"http_{error.code}"
        raise DeliveryError(category) from None
    except URLError as error:
        raise DeliveryError(_network_category(error.reason)) from None
    except http.client.HTTPException:
        raise DeliveryError("invalid_http_response") from None
    except (socket.timeout, TimeoutError):
        raise DeliveryError("timeout") from None
    except OSError:
        raise DeliveryError("connection_error") from None

    if status != 200:
        raise DeliveryError(f"http_{status}")
    if len(response_body) > MAX_RESPONSE_BYTES:
        raise DeliveryError("response_too_large")
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DeliveryError("invalid_response") from None
    if not isinstance(payload, dict):
        raise DeliveryError("invalid_response")
    code = payload.get("code", payload.get("StatusCode"))
    if not isinstance(code, int) or isinstance(code, bool) or code != 0:
        raise DeliveryError("api_error")


def deliver_pending(
    state: ProbeState,
    sender: Callable[[Notification], None],
) -> None:
    if not state.outbox:
        return
    notification = state.outbox[0]
    sender(notification)
    state.outbox.pop(0)


def _write_log(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def run_cycle(
    config: ProbeConfig,
    checked_at: Optional[datetime] = None,
    probe: Callable[[ProbeConfig], CheckResult] = probe_target,
    sender: Optional[Callable[[Notification], None]] = None,
) -> int:
    now = datetime.now(timezone.utc) if checked_at is None else checked_at
    state = load_state(config.state_path)
    result = probe(config)
    record_result(state, result, now)
    save_state(config.state_path, state)

    delivery_error: Optional[str] = None
    if sender is None:
        sender = lambda notification: send_feishu(config, notification)
    try:
        deliver_pending(state, sender)
    except DeliveryError as error:
        delivery_error = str(error) or "delivery_error"
    except Exception:
        delivery_error = "delivery_error"
    else:
        save_state(config.state_path, state)

    succeeded = (
        result.ok
        and state.status == "normal"
        and not state.outbox
        and delivery_error is None
    )
    _write_log({
        "event": "production_external_probe",
        "result": "success" if succeeded else "failure",
        "category": result.category,
        "state": state.status,
        "incidentId": state.incident_id,
        "deliveryError": delivery_error,
        "deliveryPending": len(state.outbox),
    })
    return 0 if succeeded else 1


def main(environment: Optional[Mapping[str, str]] = None) -> int:
    try:
        config = load_config(environment)
        return run_cycle(config)
    except ConfigError:
        _write_log({
            "event": "production_external_probe",
            "result": "configuration_error",
        })
        return 2
    except StateError:
        _write_log({
            "event": "production_external_probe",
            "result": "state_error",
        })
        return 2
    except Exception:
        _write_log({
            "event": "production_external_probe",
            "result": "internal_error",
        })
        return 2


if __name__ == "__main__":
    sys.exit(main())
