from __future__ import annotations

import argparse

import uvicorn

from threatprism.api.app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatPrism API runner")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    uvicorn.run(create_app(), host=args.host, port=args.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
