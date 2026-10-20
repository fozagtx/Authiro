"""Gate CLI: keygen, check, pending, approve, deny, freeze, receipt, verify -c."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from typer.testing import CliRunner

from authiro.approvals import ApprovalStore, generate_key_pair
from authiro.cli import app
from authiro.risk import args_hash

runner = CliRunner()

CLOUD_SCRIPT = """
from fastmcp import FastMCP

mcp = FastMCP("cloud")


@mcp.tool
def list_volumes() -> dict:
    return {"volumes": ["stg-db", "prod-db"]}


@mcp.tool
def backup_volume(volume_id: str, destination: str) -> dict:
    return {"backed_up": volume_id, "destination": destination}


@mcp.tool
def delete_volume(volume_id: str) -> dict:
    return {"deleted": volume_id}


if __name__ == "__main__":
    mcp.run(transport="stdio")
"""


def _gate_yaml(tmp_path: Path, state_dir: Path, public_key: Path) -> Path:
    path = tmp_path / "authiro.yaml"
    path.write_text(
        yaml.dump(
            {
                "name": "cli-gate",
                "environment": "staging",
                "state_dir": str(state_dir),
                "approver_public_key": str(public_key),
                "approval_ttl": 900,
                "upstreams": {
                    "cloud": {"command": sys.executable, "args": [str(tmp_path / "cloud.py")]}
                },
                "rules": [
                    {
                        "name": "staging-only",
                        "when": {"tool": "cloud_*"},
                        "scope": {"volume_id": {"allow": ["stg-*"]}},
                    }
                ],
            }
        )
    )
    return path


def _setup(tmp_path: Path):
    """A gate dir with keys, config, and a stdio cloud upstream script."""
    private, public = generate_key_pair(tmp_path, prefix="approver")
    state = tmp_path / "state"
    (tmp_path / "cloud.py").write_text(CLOUD_SCRIPT)
    cfg = _gate_yaml(tmp_path, state, public)
    return {"private": private, "public": public, "state": state, "config": cfg}


# ── keygen ────────────────────────────────────────────────────────────────


def test_keygen_writes_keypair(tmp_path):
    out = tmp_path / "keys"
    result = runner.invoke(app, ["keygen", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "approver.key").exists()
    assert (out / "approver.pub").exists()


# ── freeze ─────────────────────────────────────────────────────────────────


def test_freeze_on_off_status(tmp_path):
    setup = _setup(tmp_path)
    cfg = setup["config"]
    state = setup["state"]
    assert runner.invoke(app, ["freeze", "status", "-c", str(cfg)]).exit_code == 0
    on = runner.invoke(app, ["freeze", "on", "-c", str(cfg)])
    assert on.exit_code == 0 and (state / "freeze").exists()
    status = runner.invoke(app, ["freeze", "status", "-c", str(cfg)])
    assert "frozen" in status.output
    off = runner.invoke(app, ["freeze", "off", "-c", str(cfg)])
    assert off.exit_code == 0 and not (state / "freeze").exists()


def test_freeze_bad_action(tmp_path):
    setup = _setup(tmp_path)
    result = runner.invoke(app, ["freeze", "sideways", "-c", str(setup["config"])])
    assert result.exit_code != 0


# ── pending / approve / deny ───────────────────────────────────────────────


def _file_request(setup):
    store = ApprovalStore(
        setup["state"] / "approvals.db",
        gate="cli-gate",
        environment="staging",
        ttl=900,
        public_key_pem=setup["public"].read_bytes(),
    )
    return store.get_or_create(
        "cloud_delete_volume",
        args_hash({"volume_id": "stg-db"}),
        risk="destructive",
        args_redacted={"volume_id": "stg-db"},
    ), store


def test_pending_lists_requests(tmp_path):
    setup = _setup(tmp_path)
    request, _ = _file_request(setup)
    result = runner.invoke(app, ["pending", "-c", str(setup["config"])])
    assert result.exit_code == 0, result.output
    assert request.id in result.output
    assert "cloud_delete_volume" in result.output


def test_approve_signs_and_ledgers(tmp_path):
    setup = _setup(tmp_path)
    request, store = _file_request(setup)
    result = runner.invoke(
        app,
        ["approve", request.id, "-c", str(setup["config"]), "--key", str(setup["private"])],
    )
    assert result.exit_code == 0, result.output
    approved = store.get(request.id)
    assert approved is not None and approved.status == "approved"
    # the approval event is in the gate ledger
    events = [json.loads(ln) for ln in (setup["state"] / "ledger.jsonl").read_text().splitlines()]
    assert any(e.get("kind") == "approval" and e.get("request_id") == request.id for e in events)


def test_deny(tmp_path):
    setup = _setup(tmp_path)
    request, store = _file_request(setup)
    result = runner.invoke(app, ["deny", request.id, "-c", str(setup["config"])])
    assert result.exit_code == 0, result.output
    denied = store.get(request.id)
    assert denied is not None and denied.status == "denied"


def test_approve_unknown_id_fails(tmp_path):
    setup = _setup(tmp_path)
    result = runner.invoke(
        app,
        ["approve", "nope", "-c", str(setup["config"]), "--key", str(setup["private"])],
    )
    assert result.exit_code != 0


# ── receipt / verify ──────────────────────────────────────────────────────


def _gate_ledger(setup):  # type: ignore[no-untyped-def]
    from authiro.ledger import GateLedger

    return GateLedger(setup["state"], gate="cli-gate", environment="staging")


def test_receipt_prints_ledger(tmp_path):
    setup = _setup(tmp_path)
    ledger = _gate_ledger(setup)
    ledger.append({"kind": "call", "tool": "cloud_list_volumes", "args": {}})
    ledger.append({"kind": "result", "tool": "cloud_list_volumes", "status": "ok"})
    ledger.append(
        {
            "kind": "refusal",
            "tool": "cloud_delete_volume",
            "args": {"volume_id": "prod-db"},
            "reasons": [],
        }
    )
    result = runner.invoke(app, ["receipt", "-c", str(setup["config"])])
    assert result.exit_code == 0, result.output
    assert "cloud_list_volumes" in result.output
    assert "refused" in result.output


def test_verify_gate_ok_and_tampered(tmp_path):
    setup = _setup(tmp_path)
    ledger = _gate_ledger(setup)
    for tool in ("a", "b", "c"):
        ledger.append({"kind": "call", "tool": tool, "args": {}})
        ledger.append({"kind": "result", "tool": tool, "status": "ok"})

    ok = runner.invoke(app, ["verify", "-c", str(setup["config"])])
    assert ok.exit_code == 0, ok.output

    # The agent deletes ledger lines to hide the last calls.
    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text("\n".join(lines[:-2]) + "\n")
    tampered = runner.invoke(app, ["verify", "-c", str(setup["config"])])
    assert tampered.exit_code != 0
    assert "truncation" in tampered.output


# ── check ──────────────────────────────────────────────────────────────────


def test_check_classifies_upstream_tools(tmp_path):
    setup = _setup(tmp_path)
    result = runner.invoke(app, ["check", "-c", str(setup["config"])])
    assert result.exit_code == 0, result.output
    assert "cloud_delete_volume" in result.output
    assert "destructive" in result.output
    assert "cloud_list_volumes" in result.output


def test_check_requires_config():
    result = runner.invoke(app, ["check"])
    assert result.exit_code != 0


# ── serve -c smoke: the config path mounts a proxy ─────────────────────────


def test_serve_config_builds_proxy(tmp_path):
    """`serve -c` resolves to a mounted proxy (mounted here, not run)."""
    setup = _setup(tmp_path)
    from authiro.config import load_config
    from authiro.proxy import mount_proxy

    config = load_config(setup["config"])
    server = mount_proxy(config.upstreams, config=config)
    assert server is not None
