from __future__ import annotations

from threatprism.cases.schemas import IOC
from threatprism.enrichment.stubs import PROVIDERS, not_configured_enrichment


def test_enrichment_stubs_return_not_configured_for_each_provider() -> None:
    ioc = IOC(ioc_type="ip", value="203.0.113.42", confidence=0.7)

    results = not_configured_enrichment([ioc])

    assert {result["provider"] for result in results} == set(PROVIDERS)
    assert all(result["status"] == "not_configured" for result in results)
    assert all(result["ioc_type"] == "ip" for result in results)
    assert all(result["value"] == "203.0.113.42" for result in results)
