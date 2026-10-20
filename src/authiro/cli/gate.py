"""``authiro`` gate commands: keygen, check, pending, approve, deny, freeze, receipt.

These are the out-of-band human tools around a running gate: the approver
signs destructive calls here, the operator freezes and thaws, and anyone
can pull a receipt straight from the tamper-evident ledger. Every command
takes ``-c/--config`` pointing at the gate's YAML so it resolves the same
``state_dir``, gate name, and environment the running gate uses.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

from authiro.cli._branding import console, err_console
from authiro.config import GateConfig, load_config

if TYPE_CHECKING:
    from authiro.approvals import ApprovalStore
    from authiro.ledger import GateLedger

ConfigOpt = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        help="Gate YAML (state dir, environment, upstreams, rules).",
    ),
]


def _gate_config(config: ConfigOpt) -> GateConfig:
    if config is None:
        raise typer.BadParameter("gate commands need -c/--config <gate.yaml>")
    try:
        return load_config(config)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _gate_ledger_of(config: GateConfig) -> GateLedger:
    from authiro.ledger import GateLedger

    return GateLedger(config.resolved_state_dir(), gate=config.name, environment=config.environment)


def _private_key_path(config: GateConfig, key: Path | None) -> Path:
    if key is not None:
        return key
    candidates = [
        config.resolved_state_dir().parent / "approver.key",
        Path.cwd() / "approver.key",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise typer.BadParameter(
        "approver private key not found; pass --key <path> (generate one with `authiro keygen`)"
    )


# ── keygen ─────────────────────────────────────────────────────────────────


def keygen(
    out_dir: Annotated[
        Path,
        typer.Option(
            "--out",
            "-o",
            help="Directory to write the keypair into (created if missing).",
        ),
    ] = Path("approver"),
) -> None:
    """Generate an Ed25519 approval keypair: ``approver.key`` + ``approver.pub``.

    The private key stays with the human (mode 0600); the public key goes
    in the gate's YAML as ``approver_public_key``. The gate can verify
    signatures but never produce one.
    """
    from authiro.approvals import generate_key_pair

    private, public = generate_key_pair(out_dir)
    console.print(f"[bold]private key[/] {private}  [muted](keep this off the agent's machine)[/]")
    console.print(f"[bold]public key[/]  {public}  [muted](set approver_public_key to this)[/]")


# ── check ──────────────────────────────────────────────────────────────────


def check(
    config: ConfigOpt = None,
) -> None:
    """Print every proxied tool's risk classification and its source.

    Connects to each upstream the way the gate does, lists its tools,
    and classifies each: operator override, upstream annotation, verb in
    the name, or the fail-closed default. This is the command to run
    after writing (or doubting) a policy: it shows exactly what the gate
    will refuse, allow, or hold for approval.
    """
    cfg = _gate_config(config)

    async def _run() -> list[tuple[str, str, str, str]]:
        from authiro.risk import RiskClassifier
        from authiro.upstream import UpstreamManager

        classifier = RiskClassifier(cfg.risk_overrides)
        manager = UpstreamManager(cfg.upstreams)
        rows: list[tuple[str, str, str, str]] = []
        try:
            for server in manager.server_names:
                try:
                    tools = await manager.list_tools(server)
                except Exception as exc:
                    rows.append((f"{server}: UNAVAILABLE", "", "", str(exc)[:60]))
                    continue
                for t in tools:
                    result = classifier.classify(
                        f"{server}_{t.name}",
                        annotations=getattr(t, "annotations", None),
                        name_for_verbs=t.name,
                    )
                    rows.append((f"{server}_{t.name}", result.risk, result.source, result.detail))
        finally:
            await manager.aclose()
        return rows

    rows = asyncio.run(_run())
    if not rows:
        console.print("[muted]no upstreams configured[/]")
        raise typer.Exit()
    for name, risk, source, detail in rows:
        color = {"read": "green", "write": "yellow", "destructive": "red"}.get(risk, "magenta")
        console.print(f"[{color}]{risk:<11}[/] {name:<40} [muted]({source}) {detail}[/]")


# ── pending / approve / deny ───────────────────────────────────────────────


def _approval_store_of(config: GateConfig) -> ApprovalStore:
    from authiro.approvals import ApprovalStore

    return ApprovalStore(
        config.resolved_state_dir() / "approvals.db",
        gate=config.name,
        environment=config.environment,
        ttl=config.approval_ttl,
    )


def pending(config: ConfigOpt = None) -> None:
    """List approval requests waiting for a human."""
    cfg = _gate_config(config)
    requests = _approval_store_of(cfg).pending()
    if not requests:
        console.print("[muted]no pending approvals[/]")
        return
    for r in requests:
        console.print(
            f"[bold]{r.id}[/] {r.tool}  risk={r.risk} env={r.environment}\n"
            f"    args: {json.dumps(r.args_redacted, default=str)}\n"
            f"    approve: [bold]authiro approve {r.id} -c {config}[/]"
        )


def approve(
    request_id: Annotated[str, typer.Argument(help="The approval id from the refusal.")],
    config: ConfigOpt = None,
    key: Annotated[
        Path | None,
        typer.Option("--key", "-k", help="Approver private key (default: approver.key)."),
    ] = None,
) -> None:
    """Sign a pending approval with the human's Ed25519 private key.

    The signature covers the request's exact payload — gate, environment,
    tool, and the arguments' hash — so it cannot be replayed against a
    different call. The approval expires (default 15 minutes) and is
    consumed by the first matching call.
    """
    from authiro.approvals import sign_payload

    cfg = _gate_config(config)
    store = _approval_store_of(cfg)
    request = store.get(request_id)
    if request is None:
        err_console.print(f"no approval request {request_id!r}")
        raise typer.Exit(code=1)
    if request.status != "pending":
        err_console.print(f"request {request_id} is {request.status}, not pending")
        raise typer.Exit(code=1)
    key_path = _private_key_path(cfg, key)
    signature = sign_payload(key_path.read_bytes(), request.payload)
    store.approve(request_id, signature)
    ledger = _gate_ledger_of(cfg)
    ledger.append(
        {
            "kind": "approval",
            "action": "approved",
            "request_id": request_id,
            "tool": request.tool,
        }
    )
    console.print(
        f"[green]approved[/] {request.tool} (request {request_id})\n"
        f"    args: {json.dumps(request.args_redacted, default=str)}\n"
        f"    expires in {cfg.approval_ttl}s; single use."
    )


def deny(
    request_id: Annotated[str, typer.Argument(help="The approval id from the refusal.")],
    config: ConfigOpt = None,
) -> None:
    """Deny a pending approval request."""
    cfg = _gate_config(config)
    store = _approval_store_of(cfg)
    try:
        request = store.deny(request_id)
    except (KeyError, ValueError) as exc:
        err_console.print(str(exc))
        raise typer.Exit(code=1) from exc
    ledger = _gate_ledger_of(cfg)
    ledger.append(
        {
            "kind": "approval",
            "action": "denied",
            "request_id": request_id,
            "tool": request.tool,
        }
    )
    console.print(f"[red]denied[/] {request.tool} (request {request_id})")


# ── freeze ─────────────────────────────────────────────────────────────────


def freeze(
    action: Annotated[
        str,
        typer.Argument(help="on | off | status"),
    ],
    config: ConfigOpt = None,
) -> None:
    """Toggle the gate's freeze flag at runtime (no restart needed).

    While frozen, every write and destructive call is refused with a
    reason; reads pass. The gate re-checks the flag on every call.
    """
    cfg = _gate_config(config)
    state_dir = cfg.resolved_state_dir()
    freeze_file = state_dir / "freeze"
    action_norm = action.lower()
    if action_norm == "on":
        state_dir.mkdir(parents=True, exist_ok=True)
        freeze_file.touch()
        console.print("[red]frozen[/] write and destructive calls will be refused")
    elif action_norm == "off":
        if freeze_file.exists():
            freeze_file.unlink()
        console.print("[green]thawed[/] write and destructive calls may proceed (rules apply)")
    elif action_norm == "status":
        active = freeze_file.exists() or bool(os.environ.get("AUTHIRO_FREEZE"))
        console.print("[red]frozen[/]" if active else "[green]active[/] (not frozen)")
    else:
        raise typer.BadParameter(f"unknown freeze action {action!r}; expected on|off|status")


# ── receipt ────────────────────────────────────────────────────────────────


def receipt(
    config: ConfigOpt = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit the raw receipt JSON."),
    ] = False,
) -> None:
    """Print what actually ran: executed, refused, and awaiting approval.

    Built from the tamper-evident ledger — not from anything the agent
    reported. Compare the agent's summary against this line by line.
    """
    cfg = _gate_config(config)
    ledger = _gate_ledger_of(cfg)
    events = ledger.events()
    summary = {
        "executed": sum(1 for e in events if e.get("kind") == "result" and e.get("status") == "ok"),
        "failed": sum(1 for e in events if e.get("kind") == "result" and e.get("status") != "ok"),
        "refused": sum(1 for e in events if e.get("kind") == "refusal"),
        "awaiting_approval": sum(1 for e in events if e.get("kind") == "approval_required"),
    }
    if as_json:
        gate_summary = summary
        console.print_json(
            data={
                "gate": cfg.name,
                "environment": cfg.environment,
                "summary": gate_summary,
                "entries": events,
            }
        )
        return
    console.print(f"[bold]{cfg.name}[/] ({cfg.environment}) — {ledger.seq} ledger entries")
    for key, count in summary.items():
        console.print(f"  {key.replace('_', ' '):<18} {count}")
    for event in events:
        kind = event.get("kind")
        tool = event.get("tool", "")
        detail = {
            "call": "started",
            "result": f"executed ({event.get('status')})",
            "refusal": "refused",
            "approval_required": f"awaiting approval ({event.get('request_id')})",
            "approval": f"approval {event.get('action')}",
            "approval_forged": "approval rejected (bad signature)",
        }.get(str(kind), str(kind))
        color = {
            "result": "green" if event.get("status") == "ok" else "red",
            "refusal": "red",
            "approval_required": "yellow",
            "approval": "green",
            "approval_forged": "red",
        }.get(str(kind), "white")
        console.print(f"  [{color}]{event.get('seq', 0):>4}[/] {tool:<32} {detail}")


# ── verify (gate mode) ─────────────────────────────────────────────────────


def verify_gate(
    config: ConfigOpt = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable results."),
    ] = False,
) -> None:
    """Verify the gate ledger: chain, seq, and committed head.

    Names the exact line where any edit, reorder, middle deletion, or
    tail truncation broke the ledger; a head-file MAC mismatch means
    the head itself was tampered with. Exits nonzero on any problem.
    """
    cfg = _gate_config(config)
    from authiro.ledger import verify_gate_ledger

    ledger = _gate_ledger_of(cfg)
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    if as_json:
        console.print_json(data={"gate": cfg.name, "ok": ok, "problems": problems})
    elif ok:
        console.print(f"[green]ok[/] {ledger.path} ({ledger.seq} entries, chain and head intact)")
    else:
        for problem in problems:
            err_console.print(f"[red]✗[/] {problem}")
        raise typer.Exit(code=1)
