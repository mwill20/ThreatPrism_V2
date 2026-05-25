from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from tools.fixture_factory.models import ThreatPrismSyntheticFixture


AdapterFunction = Callable[[Path, int], list[ThreatPrismSyntheticFixture]]


def get_adapter(source_id: str) -> AdapterFunction:
    normalized = source_id.strip().lower()
    if normalized in {"synthea", "synthea_sample_data"}:
        from tools.fixture_factory.adapters.synthea_adapter import convert

        return convert
    if normalized in {"otrf", "otrf_security_datasets", "mordor_legacy"}:
        from tools.fixture_factory.adapters.otrf_adapter import convert

        return convert
    if normalized in {"pint", "lakera_pint"}:
        from tools.fixture_factory.adapters.pint_adapter import convert

        return convert
    if normalized in {"giskard", "giskard_prompt_injections"}:
        from tools.fixture_factory.adapters.giskard_adapter import convert

        return convert
    raise ValueError(f"No local fixture adapter is implemented for source: {source_id}")
