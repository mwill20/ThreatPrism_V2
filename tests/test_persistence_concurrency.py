from __future__ import annotations

import threading

from threatprism.cases.schemas import CaseRecord
from threatprism.persistence.sqlite import SQLiteRepository


def _make_case(index: int) -> CaseRecord:
    return CaseRecord(
        source_case_id=f"src-{index}",
        title=f"Case {index}",
        description="synthetic concurrency fixture",
    )


def test_in_memory_repository_handles_concurrent_reads() -> None:
    """Regression: the dashboard fires many parallel detail fetches per case.

    In ``:memory:`` mode the repository shares one connection across FastAPI's
    threadpool. Without serialization, concurrent reads race the single
    underlying cursor/transaction and raise (surfacing as HTTP 500).
    """
    repo = SQLiteRepository("sqlite:///:memory:")
    cases = [_make_case(i) for i in range(10)]
    for case in cases:
        repo.save_case(case)

    errors: list[Exception] = []
    thread_count = 8
    barrier = threading.Barrier(thread_count)

    def worker() -> None:
        barrier.wait()  # release all threads at once to maximize contention
        try:
            for _ in range(50):
                for case in cases:
                    assert repo.get_case(case.case_id) is not None
                assert len(repo.list_cases()) == len(cases)
        except Exception as exc:  # noqa: BLE001 - capture to assert outside thread
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent reads raised: {errors!r}"
