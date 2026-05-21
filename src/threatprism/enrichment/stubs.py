from __future__ import annotations

from threatprism.cases.schemas import IOC


PROVIDERS = ["virustotal", "urlscan", "abuseipdb", "whois_rdap"]


def not_configured_enrichment(iocs: list[IOC]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for ioc in iocs:
        for provider in PROVIDERS:
            results.append(
                {
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "provider": provider,
                    "status": "not_configured",
                    "summary": f"{provider} is not configured for demo mode.",
                }
            )
    return results
