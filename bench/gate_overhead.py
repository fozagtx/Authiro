"""Gate overhead benchmark: the PRD's 5 ms hot-path budget.

Measures the per-call cost the gate adds on top of the upstream tool
itself, against an in-memory echo upstream:

* **baseline** — a client calls the upstream server directly.
* **gated** — the same client calls the same upstream through the
  Authiro proxy (classify + rules + ledger + forwarding).

Overhead = gated - baseline, reported as median / p99 for 10,000
calls, with ``AUTHIRO_LEDGER_FSYNC`` off (default) and on. The
destructive arm adds the approvals-store read (a call waiting for
approval; the approval itself is pre-consumed so the sqlite hit is
measured, not the human).

Run:

    uv run python bench/gate_overhead.py [n_calls]
"""

from __future__ import annotations

import asyncio
import os
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from fastmcp import Client, FastMCP

from authiro.approvals import ApprovalStore, generate_key_pair, sign_payload
from authiro.config import GateConfig, Rule, ScopeCheck
from authiro.proxy import mount_proxy
from authiro.risk import args_hash


def _upstream() -> FastMCP:
    up = FastMCP("echo")

    @up.tool
    def echo(value: str = "x") -> dict:
        """Echo a value (a stand-in for a read-only upstream tool)."""
        return {"echo": value}

    @up.tool
    def delete_thing(thing_id: str) -> dict:
        """Delete a thing (a stand-in for a destructive tool)."""
        return {"deleted": thing_id}

    return up


def _gate_config(state_dir: Path, public: Path, freeze: bool = False) -> GateConfig:
    return GateConfig(
        name="bench-gate",
        environment="bench",
        state_dir=state_dir,
        approver_public_key=str(public),
        approval_ttl=3600,
        rules=(
            Rule(
                name="bench-scope",
                when_tool="*",
                scope=(ScopeCheck(arg="thing_id", allow=("stg-*",)),),
            ),
        ),
        freeze=freeze,
    )


async def _timed(calls: list[tuple[str, dict[str, Any]]], client: Client) -> list[float]:
    durations = []
    for name, args in calls:
        t0 = time.perf_counter()
        await client.call_tool(name, args)
        durations.append((time.perf_counter() - t0) * 1000)
    return durations


def _report(label: str, baseline: list[float], gated: list[float]) -> dict[str, float]:
    pairs = sorted(g - b for b, g in zip(baseline, gated, strict=True))
    overhead = [max(0.0, p) for p in pairs]
    med = statistics.median(overhead)
    p99 = overhead[min(len(overhead) - 1, int(len(overhead) * 0.99))]
    print(
        f"{label:<28} median {med:7.3f} ms   p99 {p99:7.3f} ms   "
        f"(baseline median {statistics.median(baseline):.3f} ms, "
        f"gated median {statistics.median(gated):.3f} ms)"
    )
    return {"median_ms": med, "p99_ms": p99}


async def run(n: int, *, fsync: bool) -> dict[str, dict[str, float]]:
    if fsync:
        os.environ["AUTHIRO_LEDGER_FSYNC"] = "1"
    else:
        os.environ.pop("AUTHIRO_LEDGER_FSYNC", None)

    root = Path(tempfile.mkdtemp(prefix="gate-bench-"))
    _private, public = generate_key_pair(root / "keys")
    state = root / "state"

    upstream = _upstream()
    gate = _gate_config(state, public)
    server = mount_proxy({"echo": upstream}, config=gate)

    # Pre-approve the destructive call so the sqlite read is measured,
    # not the human wait: every delete_thing('stg-x') consumes a fresh
    # approval, so file as many as we will spend.
    store = ApprovalStore(
        state / "approvals.db",
        gate=gate.name,
        environment=gate.environment,
        ttl=3600,
        public_key_pem=(root / "keys" / "approver.pub").read_bytes(),
    )
    human = ApprovalStore(
        state / "approvals.db", gate=gate.name, environment=gate.environment, ttl=3600
    )
    signer = (root / "keys" / "approver.key").read_bytes()

    async def _spend_approval() -> None:
        request = store.get_or_create(
            "echo_delete_thing",
            args_hash({"thing_id": "stg-x"}),
            risk="destructive",
            args_redacted={"thing_id": "stg-x"},
        )
        human.approve(request.id, sign_payload(signer, request.payload))

    results: dict[str, dict[str, float]] = {}
    async with Client(upstream) as raw, Client(server) as gated:
        read_calls = [("echo", {"value": "x"})] * n
        base_read = await _timed(read_calls, raw)
        gated_read = await _timed([("echo_echo", {"value": "x"})] * n, gated)
        results["read"] = _report("read (fsync on)" if fsync else "read", base_read, gated_read)

        # destructive: pre-file one approval per call, then spend it.
        base_del = await _timed([("delete_thing", {"thing_id": "stg-x"})] * n, raw)
        gated_del: list[float] = []
        for _ in range(n):
            await _spend_approval()
            t0 = time.perf_counter()
            await gated.call_tool("echo_delete_thing", {"thing_id": "stg-x"})
            gated_del.append((time.perf_counter() - t0) * 1000)
        label = "destructive (fsync on)" if fsync else "destructive"
        results["destructive"] = _report(label, base_del, gated_del)
    os.environ.pop("AUTHIRO_LEDGER_FSYNC", None)
    return results


def main() -> None:
    n = int(__import__("sys").argv[1]) if len(__import__("sys").argv) > 1 else 10_000
    print(f"gate overhead benchmark — {n} calls per arm, in-memory upstream\n")
    asyncio.run(run(n, fsync=False))
    print()
    asyncio.run(run(n, fsync=True))


if __name__ == "__main__":
    main()
