"""Transient-error retry helper (clients.request_with_retries)."""
import pytest
import requests

from ioc_enrich.clients import request_with_retries


class FakeResp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


def seq(*outcomes):
    """A do_request callable that yields outcomes (FakeResp or an exception)."""
    it = iter(outcomes)

    def do():
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return item

    return do


def test_success_no_retry():
    sleeps = []
    resp = request_with_retries(seq(FakeResp(200)), sleep=sleeps.append)
    assert resp.status_code == 200
    assert sleeps == []


def test_no_retry_on_client_error():
    sleeps = []
    resp = request_with_retries(seq(FakeResp(400)), retries=2, sleep=sleeps.append)
    assert resp.status_code == 400
    assert sleeps == []


def test_retries_429_then_succeeds():
    sleeps = []
    resp = request_with_retries(
        seq(FakeResp(429), FakeResp(200)), retries=2, sleep=sleeps.append
    )
    assert resp.status_code == 200
    assert len(sleeps) == 1


def test_gives_up_and_returns_last_5xx():
    sleeps = []
    resp = request_with_retries(
        seq(FakeResp(503), FakeResp(503), FakeResp(503)), retries=2, sleep=sleeps.append
    )
    assert resp.status_code == 503
    assert len(sleeps) == 2


def test_retries_timeout_then_succeeds():
    sleeps = []
    resp = request_with_retries(
        seq(requests.Timeout(), FakeResp(200)), retries=2, sleep=sleeps.append
    )
    assert resp.status_code == 200
    assert len(sleeps) == 1


def test_reraises_timeout_after_exhaustion():
    sleeps = []
    with pytest.raises(requests.Timeout):
        request_with_retries(
            seq(requests.Timeout(), requests.Timeout(), requests.Timeout()),
            retries=2,
            sleep=sleeps.append,
        )
    assert len(sleeps) == 2


def test_honors_numeric_retry_after():
    sleeps = []
    request_with_retries(
        seq(FakeResp(429, {"Retry-After": "3"}), FakeResp(200)),
        retries=2,
        base_delay=1.0,
        sleep=sleeps.append,
    )
    assert sleeps == [3]


def test_retry_emits_log(caplog):
    with caplog.at_level("INFO", logger="ioc_enrich.retry"):
        request_with_retries(
            seq(FakeResp(503), FakeResp(200)), retries=2, sleep=lambda *_: None
        )
    assert any("retrying" in rec.getMessage() for rec in caplog.records)
