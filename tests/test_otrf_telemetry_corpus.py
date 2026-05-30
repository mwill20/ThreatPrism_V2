from __future__ import annotations

import json
from pathlib import Path

from threatprism.cases.schemas import CaseCreate
from threatprism.cases.service import CaseService
from threatprism.demo.seeding import (
    DATASET_ALLOWED_LICENSE_REVIEW,
    CuratedDatasetSource,
    DemoSeeder,
)
from tools.fixture_factory.adapters.otrf_adapter import (
    SAFE_FIELDS,
    _process_basename,
    _project_safe,
    _scrub_identifiers,
)
from support_settings import local_auth_disabled_settings


# Real identifier VALUES from the OTRF lab telemetry that must never reach a
# committed fixture. theshire.local is the Mordor lab domain; the rest are host,
# SID, account, collector, and raw-field markers from the source events.
FORBIDDEN_SUBSTRINGS = (
    "theshire",
    "cloudapp",
    "WORKSTATION5",
    "wec.internal",
    "S-1-5-21",
    "S-1-5-18",
    "pgustavo",
    "NT AUTHORITY",
    '"Hostname"',
    '"AccountName"',
    '"UserID"',
    '"Domain"',
    '"port"',
    '"TargetObject"',
    '"RecordNumber"',
    '"ProcessGuid"',
)

_OTRF_PATH = Path("fixtures/curated_datasets/otrf_soc_telemetry.jsonl")


def _otrf_seeds():
    return [
        seed
        for seed in CuratedDatasetSource().list_demo_fixtures()
        if seed.fixture_id == "otrf_soc_telemetry"
    ]


def test_mit_lab_telemetry_status_is_allowlisted_in_code() -> None:
    # The authoritative gate lives in code, not the manifest.
    assert "approved_third_party_mit_lab_telemetry" in DATASET_ALLOWED_LICENSE_REVIEW


def test_committed_otrf_fixtures_load_and_validate() -> None:
    seeds = _otrf_seeds()
    assert len(seeds) == 8
    assert len({seed.source_case_id for seed in seeds}) == 8
    for seed in seeds:
        CaseCreate.model_validate(seed.payload)


def test_committed_otrf_file_has_no_raw_identifiers() -> None:
    blob = _OTRF_PATH.read_text(encoding="utf-8")
    leaks = [token for token in FORBIDDEN_SUBSTRINGS if token in blob]
    assert leaks == [], f"OTRF fixture leaked raw identifiers: {leaks}"


def test_safe_projection_drops_identifying_fields() -> None:
    raw = {
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "host": "wec.internal.cloudapp.net",
        "Hostname": "WORKSTATION5.theshire.local",
        "UserID": "S-1-5-21-4228717743-1032521047-1810997296-1104",
        "AccountName": "pgustavo",
        "Domain": "THESHIRE",
        "port": 64545,
        "TargetObject": "HKU\\S-1-5-21-4228717743-1032521047-1810997296-1104\\Software",
    }
    projected = _project_safe(raw)
    assert set(projected) <= SAFE_FIELDS
    assert "host" not in projected and "Hostname" not in projected
    assert "UserID" not in projected and "AccountName" not in projected
    assert "TargetObject" not in projected and "port" not in projected


def test_sid_and_user_path_scrubbed_as_defense_in_depth() -> None:
    scrubbed = _scrub_identifiers(
        {
            "RuleName": "sid=S-1-5-21-4228717743-1032521047-1810997296-1104",
            "Image": "C:\\Users\\pgustavo\\evil.exe",
        }
    )
    assert "S-1-5-21" not in json.dumps(scrubbed)
    assert "pgustavo" not in json.dumps(scrubbed)
    assert "[REDACTED_SID]" in scrubbed["RuleName"]
    assert "[REDACTED_USER]" in scrubbed["Image"]


def test_process_basename_is_not_mangled_into_a_domain() -> None:
    # Regression: the shared domain normalizer used to rewrite "powershell.exe"
    # to a documentation domain. The basename is attached after sanitization.
    assert _process_basename("C:\\windows\\System32\\powershell.exe") == "powershell.exe"
    assert _process_basename("C:\\Users\\victim\\lsass.exe") == "lsass.exe"
    blob = _OTRF_PATH.read_text(encoding="utf-8")
    assert "example.org" not in blob
    assert "powershell.exe" in blob


def test_otrf_seeds_through_real_intake() -> None:
    service = CaseService(local_auth_disabled_settings())

    result = DemoSeeder(service).seed([CuratedDatasetSource()])

    seeded_ids = {outcome.source_case_id for outcome in result.seeded}
    otrf_ids = {seed.source_case_id for seed in _otrf_seeds()}
    assert otrf_ids <= seeded_ids
