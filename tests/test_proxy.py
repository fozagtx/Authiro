"""Proxy mode end to end: the PocketOS replay as tests.

An in-memory FastMCP "cloud" server stands in for a real cloud
provider; the gate wraps it and an MCP client (the agent) connects
only to the gate. Every refusal shape, the approval flow, and the
ledger trail are asserted from the agent's side of the wire.
"""

from __future__ import annotations

import json

import pytest
from fastmcp import Client, FastMCP

from authiro.approvals import ApprovalStore, generate_key_pair, sign_payload
from authiro.config import load_config
from authiro.ledger import verify_gate_ledger
from authiro.proxy import Gate, mount_proxy


def _cloud_server() -> FastMCP:
    """The fake cloud provider: volumes, backups, SQL — and a state file."""
    cloud = FastMCP("cloud")

    @cloud.tool
    def list_volumes() -> dict:
        return {"volumes": ["stg-db", "prod-db"]}

    @cloud.tool
    def run_sql(sql: str) -> dict:
        return {"rows_affected": 0, "sql": sql[:40]}

    @cloud.tool
    def backup_volume(volume_id: str, destination: str, auth_token: str = "") -> dict:
        return {"backed_up": volume_id, "destination": destination}

    @cloud.tool
    def delete_volume(volume_id: str, auth_token: str = "") -> dict:
        return {"deleted": volume_id}

    return cloud


POCKETOS_YAML = """
name: pocketos-gate
environment: staging
state_dir: {state_dir}
approver_public_key: {public_key}
approval_ttl: 900
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


@pytest.fixture()
def gate_setup(tmp_path):
    private, public = generate_key_pair(tmp_path, prefix="approver")
    state = tmp_path / "state"
    cfg_path = tmp_path / "authiro.yaml"
    cfg_path.write_text(POCKETOS_YAML.format(state_dir=str(state), public_key=str(public)))
    config = load_config(cfg_path)
    server = mount_proxy({"cloud": _cloud_server()}, config=config)
    store = ApprovalStore(
        state / "approvals.db",
        gate=config.name,
        environment=config.environment,
        ttl=config.approval_ttl,
    )
    return {
        "server": server,
        "config": config,
        "store": store,
        "private": private.read_bytes(),
        "state": state,
        "gate_yaml": cfg_path,
    }


async def _call(server, tool, args):
    async with Client(server) as client:
        return await client.call_tool(tool, args)


def _body(result) -> dict:
    assert result.structured_content is not None, result.content
    return result.structured_content


# ── R1: proxy surface ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_sees_namespaced_tools(gate_setup):
    async with Client(gate_setup["server"]) as client:
        tools = await client.list_tools()
    names = [t.name for t in tools]
    assert "cloud_delete_volume" in names
    assert "cloud_backup_volume" in names
    assert "cloud_run_sql" in names
    assert "delete_volume" not in names  # only the namespaced surface


@pytest.mark.asyncio
async def test_tool_descriptions_carry_risk_notes(gate_setup):
    async with Client(gate_setup["server"]) as client:
        tools = await client.list_tools()
    by_name = {t.name: t for t in tools}
    assert "[authiro] risk: destructive" in (by_name["cloud_delete_volume"].description or "")
    assert "signed human approval" in (by_name["cloud_delete_volume"].description or "")
    assert "[authiro] risk: write" in (by_name["cloud_backup_volume"].description or "")


@pytest.mark.asyncio
async def test_read_call_passes_through(gate_setup):
    result = await _call(gate_setup["server"], "cloud_list_volumes", {})
    body = _body(result)
    assert "stg-db" in body["volumes"]
    assert not result.is_error


# ── Refusal shapes ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_out_of_scope_prod_refused(gate_setup):
    """PocketOS beat 1: delete_volume(prod-db) never reaches the cloud."""
    result = await _call(gate_setup["server"], "cloud_delete_volume", {"volume_id": "prod-db"})
    body = _body(result)
    assert body["authiro"] == "refused"
    assert body["tool"] == "cloud_delete_volume"
    assert body["risk"] == "destructive"
    scope = [r for r in body["reasons"] if r["kind"] == "scope"]
    assert scope and "prod-db" in scope[0]["message"]
    assert all(r["fix"] for r in body["reasons"])
    # Ground-truth context rides along (R11)
    assert body["context"]["environment"] == "staging"
    assert body["context"]["freeze"] is False
    assert body["context"]["today"]


@pytest.mark.asyncio
async def test_sql_drop_escalates_to_destructive(gate_setup):
    """PocketOS beat 2: run_sql('DROP TABLE users') needs approval."""
    result = await _call(gate_setup["server"], "cloud_run_sql", {"sql": "DROP TABLE users"})
    body = _body(result)
    assert body["authiro"] == "approval_required"
    assert body["risk"] == "destructive"
    result_ok = await _call(gate_setup["server"], "cloud_run_sql", {"sql": "SELECT 1"})
    assert not result_ok.is_error


@pytest.mark.asyncio
async def test_delete_stg_needs_offsite_backup_first(gate_setup):
    """PocketOS beat 3: an on-volume backup does not count."""
    await _call(
        gate_setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "on-volume"},
    )
    result = await _call(gate_setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(result)
    assert body["authiro"] == "refused"
    prereq = [r for r in body["reasons"] if r["kind"] == "prerequisite"]
    assert prereq and "cloud_backup_volume" in prereq[0]["fix"]
    assert "offsite" in prereq[0]["fix"]


@pytest.mark.asyncio
async def test_offsite_backup_unlocks_approval_request(gate_setup):
    """PocketOS beat 4: after the offsite backup, approval_required with id."""
    await _call(
        gate_setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    result = await _call(gate_setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(result)
    assert body["authiro"] == "approval_required"
    approval = body["approval"]
    assert approval["id"]
    assert "authiro approve" in approval["how_to_approve"]


# ── Approvals: forgery, human sign-off, single use ────────────────────────


@pytest.mark.asyncio
async def test_forged_approval_rejected_and_logged(gate_setup):
    """PocketOS beat 5: the agent edits the approvals DB; rejected."""
    setup = gate_setup
    await _call(
        setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    result = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    request_id = _body(result)["approval"]["id"]

    # The agent flips the row to approved directly in sqlite.
    import sqlite3
    import time as _time

    conn = sqlite3.connect(setup["state"] / "approvals.db")
    conn.execute(
        "UPDATE approval_requests SET status='approved', signature='forged', "
        "approved_at=?, expires_at=? WHERE id=?",
        (_time.time(), _time.time() + 9999, request_id),
    )
    conn.commit()
    conn.close()

    result2 = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(result2)
    assert body["authiro"] == "refused"
    assert "signature" in body["reasons"][0]["message"]

    # ...and the tampering is in the ledger.
    gate = _gate_of(setup["server"])
    kinds = [e["kind"] for e in gate.ledger.events()]
    assert "approval_forged" in kinds


@pytest.mark.asyncio
async def test_human_approval_executes_once(gate_setup):
    """PocketOS beat 6: approve → runs once; retry needs a new approval."""
    setup = gate_setup
    await _call(
        setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    result = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    request_id = _body(result)["approval"]["id"]

    # The human signs out of band.
    store = ApprovalStore(
        setup["state"] / "approvals.db",
        gate=setup["config"].name,
        environment=setup["config"].environment,
    )
    request = store.get(request_id)
    assert request is not None
    store.approve(request_id, sign_payload(setup["private"], request.payload))

    # The retry executes.
    executed = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(executed)
    assert body["deleted"] == "stg-db"

    # An identical retry needs a new approval (single use).
    again = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body2 = _body(again)
    assert body2["authiro"] == "approval_required"
    assert body2["approval"]["id"] != request_id


@pytest.mark.asyncio
async def test_approval_signed_with_wrong_key_rejected(gate_setup, tmp_path):
    """A signature from any key but the configured approver never unlocks."""
    setup = gate_setup
    await _call(
        setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    result = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    request_id = _body(result)["approval"]["id"]
    impostor_private, _ = generate_key_pair(tmp_path, prefix="impostor")
    store = ApprovalStore(
        setup["state"] / "approvals.db",
        gate=setup["config"].name,
        environment=setup["config"].environment,
    )
    request = store.get(request_id)
    assert request is not None
    store.approve(request_id, sign_payload(impostor_private.read_bytes(), request.payload))
    again = await _call(setup["server"], "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(again)
    assert body["authiro"] == "refused"
    assert "signature" in body["reasons"][0]["message"]


# ── Freeze ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_freeze_file_blocks_writes_without_restart(gate_setup):
    gate = _gate_of(gate_setup["server"])
    assert await _call(
        gate_setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    gate.set_freeze(True)
    try:
        frozen = await _call(
            gate_setup["server"],
            "cloud_backup_volume",
            {"volume_id": "stg-db", "destination": "offsite"},
        )
        body = _body(frozen)
        assert body["authiro"] == "refused"
        assert any(r["kind"] == "freeze" for r in body["reasons"])
        # reads still pass
        ok = await _call(gate_setup["server"], "cloud_list_volumes", {})
        assert not ok.is_error
    finally:
        gate.set_freeze(False)
    thawed = await _call(
        gate_setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    assert not thawed.is_error


# ── Resources: context and receipt ────────────────────────────────────────


@pytest.mark.asyncio
async def test_context_resource(gate_setup):
    async with Client(gate_setup["server"]) as client:
        text = (await client.read_resource("authiro://context"))[0].text
    context = json.loads(text)
    assert context["environment"] == "staging"
    assert context["today"]
    assert context["freeze"] is False


@pytest.mark.asyncio
async def test_receipt_resource_lists_attempts(gate_setup):
    await _call(gate_setup["server"], "cloud_delete_volume", {"volume_id": "prod-db"})
    await _call(gate_setup["server"], "cloud_list_volumes", {})
    async with Client(gate_setup["server"]) as client:
        text = (await client.read_resource("authiro://receipt"))[0].text
    receipt = json.loads(text)
    assert receipt["summary"]["refused"] >= 1
    assert receipt["summary"]["executed"] >= 1
    statuses = {e["status"] for e in receipt["entries"]}
    assert any(s.startswith("refused") or s == "refused" for s in statuses)


# ── Ledger and redaction ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ledger_records_and_verifies(gate_setup):
    await _call(gate_setup["server"], "cloud_delete_volume", {"volume_id": "prod-db"})
    await _call(gate_setup["server"], "cloud_list_volumes", {})
    gate = _gate_of(gate_setup["server"])
    ok, problems = verify_gate_ledger(
        gate.ledger.path,
        gate.ledger.head_path,
        key=gate.ledger.key,
        expected_binding=gate.ledger.binding,
    )
    assert ok, problems
    kinds = [e["kind"] for e in gate.ledger.events()]
    assert "refusal" in kinds
    assert "result" in kinds


@pytest.mark.asyncio
async def test_secrets_redacted_in_ledger_and_approval(gate_setup):
    await _call(
        gate_setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite", "auth_token": "super-secret"},
    )
    gate = _gate_of(gate_setup["server"])
    raw = gate.ledger.path.read_text()
    assert "super-secret" not in raw
    assert "[REDACTED]" in raw
    # and the approval prompt shows the redacted copy
    result = await _call(
        gate_setup["server"],
        "cloud_delete_volume",
        {"volume_id": "stg-db", "auth_token": "hunter2"},
    )
    request_id = _body(result)["approval"]["id"]
    request = gate_setup["store"].get(request_id)
    assert request is not None
    assert request.args_redacted.get("auth_token") == "[REDACTED]"
    assert request.args_redacted.get("volume_id") == "stg-db"


@pytest.mark.asyncio
async def test_history_rebuilt_after_restart(gate_setup):
    """A backup made before a restart still satisfies the delete's prereq."""
    setup = gate_setup
    await _call(
        setup["server"],
        "cloud_backup_volume",
        {"volume_id": "stg-db", "destination": "offsite"},
    )
    # Simulate a restart: rebuild the gate from the same state dir.
    config = load_config(setup["gate_yaml"])
    server2 = mount_proxy({"cloud": _cloud_server()}, config=config)
    result = await _call(server2, "cloud_delete_volume", {"volume_id": "stg-db"})
    body = _body(result)
    assert body["authiro"] == "approval_required"  # prereq survived the restart
    assert not any(r["kind"] == "prerequisite" for r in body["reasons"])


def _gate_of(server) -> Gate:
    for middleware_holder in getattr(server, "middleware", []):
        gate = getattr(middleware_holder, "_gate", None)
        if isinstance(gate, Gate):
            return gate
    raise AssertionError("gate middleware not found on server")
