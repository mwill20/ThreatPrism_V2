from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from threatprism.api.app import _run_triage_with_limit, create_app
from support_settings import local_auth_disabled_settings


def _payload(index: int = 1) -> dict:
    payload = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8"))
    payload["source_case_id"] = f"SOAR-LIMITS-{index:03d}"
    return payload


def test_post_cases_rejects_oversized_body_before_validation() -> None:
    app = create_app(local_auth_disabled_settings(max_request_body_bytes=128))
    client = TestClient(app)

    response = client.post(
        "/cases",
        content=b'{"description":"' + (b"x" * 512) + b'"}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large."


def test_post_cases_rate_limit_returns_429() -> None:
    app = create_app(
        local_auth_disabled_settings(
            max_request_body_bytes=262_144,
            case_post_rate_limit_per_minute=2,
        )
    )
    client = TestClient(app)

    assert client.post("/cases", json=_payload(1)).status_code == 202
    assert client.post("/cases", json=_payload(2)).status_code == 202
    response = client.post("/cases", json=_payload(3))

    assert response.status_code == 429
    assert response.json()["detail"] == "POST /cases rate limit exceeded."


def test_triage_runner_honors_concurrency_cap() -> None:
    class TrackingService:
        def __init__(self) -> None:
            self.active = 0
            self.max_active = 0
            self.calls = 0
            self.lock = threading.Lock()

        def run_triage(self, case_id: str) -> None:
            with self.lock:
                self.calls += 1
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            time.sleep(0.05)
            with self.lock:
                self.active -= 1

    service = TrackingService()
    semaphore = threading.BoundedSemaphore(2)
    threads = [
        threading.Thread(target=_run_triage_with_limit, args=(service, f"case_{index}", semaphore))
        for index in range(8)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert service.calls == 8
    assert service.max_active <= 2
