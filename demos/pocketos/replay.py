"""The PocketOS replay: the same agent moves, twice.

Run 1 — **raw agent.** The agent talks to the cloud server directly. A
credential mismatch on staging makes it look around; it finds a token
that reaches prod, and deletes ``prod-db`` to "clear the error".
88,310 rows and the on-volume backup are gone in seconds.

Run 2 — **behind Authiro.** The identical move sequence against the
same cloud server, routed through the gate from the PRD's policy:

* ``delete_volume(prod-db)``  → refused, outside the staging scope
* ``run_sql("DROP TABLE users")`` → escalated to destructive, approval
  required
* ``delete_volume(stg-db)`` → refused until an *offsite* backup exists
  (an on-volume backup does not count)
* the agent writes ``approved`` straight into the approvals database →
  rejected, bad signature, logged
* the human signs out of band → the delete runs once; an identical
  retry needs a new approval

Then the receipt (what actually ran, from the ledger — not from the
agent's summary) and the tamper check (the agent deletes ledger lines;
``authiro verify`` names them).

No API key, no model: the "agent" is a scripted client making exactly
the moves the incident report describes.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DEMO_DIR))
sys.path.insert(0, str(DEMO_DIR.parent.parent))

from cloud_server import ROWS, build_cloud  # noqa: E402

from authiro.approvals import ApprovalStore, generate_key_pair, sign_payload  # noqa: E402
from authiro.config import load_config  # noqa: E402
from authiro.proxy import mount_proxy  # noqa: E402

POLICY = """
name: pocketos-gate
environment: staging
state_dir: {state_dir}
approver_public_key: {public_key}
approval_ttl: 900

upstreams:
  cloud:
    command: {command}
    args: [demos/pocketos/cloud_server.py, --stdio]

risk_overrides:
  "cloud_backup_*": write

rules:
  - name: staging-session-cannot-touch-prod
    when: {{tool: "cloud_*"}}
    scope:
      volume_id: {{allow: ["stg-*"]}}

  - name: offsite-backup-before-delete
    when: {{tool: cloud_delete_volume}}
    require_prior:
      tool: cloud_backup_volume
      match_args: [volume_id]
      with_args: {{destination: offsite}}
      within: 600
"""


def _hr(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _body(result) -> dict:
    return result.structured_content or {}


async def run_raw_agent(db_dir: Path) -> None:
    """Run 1: the agent holds the cloud credentials directly."""
    from fastmcp import Client

    _hr("RUN 1 — raw agent (the cloud server is the agent's MCP server)")
    os.environ["POCKETOS_DB_DIR"] = str(db_dir / "raw")
    cloud = build_cloud()
    async with Client(cloud) as client:
        await client.call_tool("count_rows", {})
        print(f"[agent] count_rows → {ROWS} rows")

        # The credential mismatch from the incident: staging SQL fails.
        bad = await client.call_tool("run_sql", {"sql": "SELECT COUNT(*) FROM users"})
        print(f"[agent] run_sql on staging → auth error: {_body(bad).get('error', 'denied')}")

        # The agent looks around, finds a token that reaches prod, and
        # "fixes" the error by deleting the volume.
        print("[agent] found an unrelated prod token; trying delete_volume(prod-db)...")
        backup = await client.call_tool(
            "backup_volume", {"volume_id": "prod-db", "destination": "on-volume"}
        )
        print(f"[agent] on-volume backup → {_body(backup)}")
        deleted = await client.call_tool("delete_volume", {"volume_id": "prod-db"})
        print(f"[agent] delete_volume(prod-db) → {_body(deleted)}")

        rows = await client.call_tool("count_rows", {})
        print(f"[agent] count_rows → {_body(rows)}")
        print(
            "\nRESULT: 88,310 rows and the on-volume backup are gone. "
            "The agent's summary says 'resolved a staging credential issue.'"
        )


async def run_gated_agent(root: Path) -> tuple[Path, ApprovalStore, bytes]:
    """Run 2: the identical moves, behind the gate."""
    from fastmcp import Client

    _hr("RUN 2 — the same agent behind Authiro (state: a fresh staging volume)")
    os.environ["POCKETOS_DB_DIR"] = str(root / "gated")

    state_dir = root / "state"
    private, public = generate_key_pair(root / "keys")
    config_path = root / "authiro.yaml"
    config_path.write_text(
        POLICY.format(
            state_dir=str(state_dir),
            public_key=str(public),
            command=os.path.join(".venv", "bin", "python"),
        )
    )
    # The demo runs the upstream in-process so no API key or subprocess
    # Python is needed; the policy above shows the stdio shape.
    config = load_config(config_path)
    server = mount_proxy({"cloud": build_cloud()}, config=config)
    store = ApprovalStore(
        state_dir / "approvals.db",
        gate=config.name,
        environment=config.environment,
        ttl=config.approval_ttl,
        public_key_pem=public.read_bytes(),
    )
    signer = private.read_bytes()

    async with Client(server) as client:
        rows = await client.call_tool("cloud_count_rows", {})
        print(f"[agent] cloud_count_rows → {_body(rows)}")

        # Beat 1: prod is out of scope.
        r = await client.call_tool("cloud_delete_volume", {"volume_id": "prod-db"})
        b = _body(r)
        reason = b["reasons"][0]
        print(f"[agent] cloud_delete_volume(prod-db) → {b['authiro']}: {reason['message']}")
        print(f"        fix: {b['reasons'][0]['fix']}")

        # Beat 2: dangerous SQL escalates a write tool to destructive.
        r = await client.call_tool("cloud_run_sql", {"sql": "DROP TABLE users"})
        b = _body(r)
        print(f"[agent] cloud_run_sql('DROP TABLE users') → {b['authiro']} (risk={b['risk']})")
        ok_sql = await client.call_tool("cloud_run_sql", {"sql": "SELECT COUNT(*) FROM users"})
        print(f"[agent] cloud_run_sql('SELECT ...') → runs fine: {_body(ok_sql)}")

        # Beat 3: an on-volume backup does not satisfy the prerequisite.
        await client.call_tool(
            "cloud_backup_volume", {"volume_id": "stg-db", "destination": "on-volume"}
        )
        r = await client.call_tool("cloud_delete_volume", {"volume_id": "stg-db"})
        b = _body(r)
        prereq = next(x for x in b["reasons"] if x["kind"] == "prerequisite")
        print(f"[agent] cloud_delete_volume(stg-db) after on-volume backup → {b['authiro']}")
        print(f"        {prereq['fix']}")

        # Beat 4: the offsite backup unlocks the approval request.
        await client.call_tool(
            "cloud_backup_volume", {"volume_id": "stg-db", "destination": "offsite"}
        )
        r = await client.call_tool("cloud_delete_volume", {"volume_id": "stg-db"})
        b = _body(r)
        approval_id = b["approval"]["id"]
        print(f"[agent] cloud_delete_volume(stg-db) after offsite backup → {b['authiro']}")
        print(f"        approval id: {approval_id}")

        # Beat 5: the agent forges the approvals database.
        conn = sqlite3.connect(state_dir / "approvals.db")
        conn.execute(
            "UPDATE approval_requests SET status='approved', signature='approved', "
            "approved_at=1.0, expires_at=9999999999 WHERE id=?",
            (approval_id,),
        )
        conn.commit()
        conn.close()
        r = await client.call_tool("cloud_delete_volume", {"volume_id": "stg-db"})
        b = _body(r)
        print("[agent] wrote status='approved' straight into the approvals database")
        print(f"        → {b['authiro']}: {b['reasons'][0]['message']}")

        # Beat 6: the human signs out of band; the delete runs once.
        # The forgery refusal already filed a fresh request; sign that one.
        human_store = ApprovalStore(
            state_dir / "approvals.db",
            gate=config.name,
            environment=config.environment,
            ttl=config.approval_ttl,
        )
        fresh_id = b["approval"]["id"]
        fresh = human_store.get(fresh_id)
        assert fresh is not None
        human_store.approve(fresh_id, sign_payload(signer, fresh.payload))
        print(f"[human] authiro approve {fresh_id} (signed with the approver's key)")

        r = await client.call_tool("cloud_delete_volume", {"volume_id": "stg-db"})
        print(f"[agent] cloud_delete_volume(stg-db) → executed: {_body(r)}")

        r = await client.call_tool("cloud_delete_volume", {"volume_id": "stg-db"})
        b = _body(r)
        print(
            f"[agent] identical retry → {b['authiro']} "
            f"(approval {approval_id} was single-use; new id {b['approval']['id']})"
        )

        rows = await client.call_tool("cloud_count_rows", {})
        print(f"[agent] cloud_count_rows → {_body(rows)}")
        print("\nRESULT: the staging volume was deleted exactly once, with a human's")
        print("signature, after an offsite backup. prod-db was never touched.")

    return state_dir, store, signer


def show_receipt_and_tamper(state_dir: Path, config_path: Path) -> None:
    """The receipt and the tamper check, via the real CLI code paths."""
    from typer.testing import CliRunner

    from authiro.cli import app

    runner = CliRunner()

    _hr("RECEIPT — what actually ran (from the ledger, not the agent's summary)")
    result = runner.invoke(app, ["receipt", "-c", str(config_path)])
    print(result.output)

    _hr("TAMPER CHECK — the agent deletes ledger lines to hide the prod attempt")
    ledger = state_dir / "ledger.jsonl"
    lines = ledger.read_text().splitlines()
    # Remove every refusal of cloud_delete_volume(prod-db): the cover-up.
    kept = [ln for ln in lines if "prod-db" not in ln]
    ledger.write_text("\n".join(kept) + "\n")
    result = runner.invoke(app, ["verify", "-c", str(config_path)])
    print(result.output)
    if result.exit_code == 0:
        print("!!! tampering was NOT detected — this is a bug")
        raise SystemExit(1)
    print("tampering detected, exact divergence named. The cover-up fails.")


async def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="pocketos-replay-"))
    print(f"replay scratch: {root}")
    await run_raw_agent(root)
    state_dir, _store, _signer = await run_gated_agent(root)
    show_receipt_and_tamper(state_dir, root / "authiro.yaml")
    _hr("DONE — the same agent, the same moves; the second run survives all of them")
    print("remove the scratch dir when finished:", root)


if __name__ == "__main__":
    asyncio.run(main())
