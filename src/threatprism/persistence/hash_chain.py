"""Generic append-only, tamper-evident hash-chained JSONL log.

Each line is ``{"payload": <dict>, "prev_hash": <hex>, "record_hash": <hex>}`` where
``record_hash = sha256(prev_hash + canonical(payload))`` and the first record's
``prev_hash`` is ``GENESIS_HASH``. Every record commits to the entire history before
it, so any later edit, deletion, or reorder changes a downstream ``record_hash`` and is
caught by ``verify()``.

This is the shared integrity primitive behind both the LLM failure log
(`llm/failure_log.py`) and the case audit trail mirror (`cases/service.py`) — one
implementation, many consumers.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

GENESIS_HASH = "0" * 64


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def record_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(payload)).encode("utf-8")).hexdigest()


@dataclass
class HashChainedLog:
    """Append-only, hash-chained JSONL sink for arbitrary JSON-serializable payloads."""

    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                last = json.loads(line).get("record_hash", last)
        return last

    def append_payload(self, payload: dict) -> dict:
        """Append one record, linking it to the prior record's hash."""
        prev_hash = self._last_hash()
        record = {
            "payload": payload,
            "prev_hash": prev_hash,
            "record_hash": record_hash(prev_hash, payload),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def payload_ids(self, id_field: str) -> set[str]:
        """Return the set of ``payload[id_field]`` already recorded (for dedup)."""
        ids: set[str] = set()
        if not self.path.exists():
            return ids
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                value = json.loads(line).get("payload", {}).get(id_field)
                if value is not None:
                    ids.add(str(value))
        return ids

    def verify(self) -> bool:
        """Recompute the chain; return False on any edit, deletion, or reorder."""
        if not self.path.exists():
            return True
        prev_hash = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("prev_hash") != prev_hash:
                    return False
                if rec.get("record_hash") != record_hash(prev_hash, rec.get("payload", {})):
                    return False
                prev_hash = rec["record_hash"]
        return True
