"""Deployment-approval FSM: typed inputs and a signed human approval gate.

Shape:

    open_change(change) --> review --> deploy(reason) --> verify
                                 \\-> reject(reason)      \\-> rollback
                                 \\-> abort                \\-> abort

Features it exercises:

* A nested Pydantic input. ``open_change`` takes ``change: ChangeRequest``
  (a ``BaseModel`` with ``service``, ``risk: Literal["low", "high"]`` and
  ``summary``). Authiro surfaces ``model_json_schema()`` under
  ``next_action_schemas`` so the caller sees the nested object shape, and
  coerces the dict the client sends into the model before dispatch.
* A ``validation_failed`` path on malformed typed input. A dict that does not
  validate as ``ChangeRequest`` (e.g. ``risk="critical"``) is refused at
  the wire boundary with per-field Pydantic errors, not an action crash.
* A **signed** escalation gate. There is no ``approve`` action for the
  agent to call — an agent that could approve its own deploy was the
  bug this example used to ship. ``deploy`` is guarded by an input
  validator that refuses unless a *human* has signed the exact call
  with an Ed25519 key the agent never holds. The refusal carries the
  pending approval id; the approval binds to the deploy reason, expires
  (default 15 minutes), and is single-use. Flipping the approvals
  database to "approved" does nothing without a valid signature.

Five actions, three terminal stages (``verified``, ``rejected``,
``rolled_back`` / ``aborted``).

The human signs out of band::

    # in one shell: the demo's stand-in for the approver CLI
    python -c "from deploy_approval import human_approve; human_approve('<id>')"

Serve over stdio::

    authiro serve deploy_approval:build --app-dir examples
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import pydantic
from burr.core import ApplicationBuilder, State, action
from burr.core.action import Condition

from authiro import ValidationFailed, tracker
from authiro.approvals import ApprovalStore, generate_key_pair, sign_payload
from authiro.risk import args_hash

_TRACKER_PROJECT = os.environ.get("AUTHIRO_PROJECT", "deploy-dogfood")

_GATE_NAME = "deploy-approval"
_GATE_ENV = "demo"
_APPROVAL_TTL = 900


class ChangeRequest(pydantic.BaseModel):
    """A change to be deployed. The nested input to ``open_change``."""

    service: str = pydantic.Field(description="Service to deploy, e.g. 'payments'.")
    risk: Literal["low", "high"] = pydantic.Field(description="Risk tier of the change.")
    summary: str = pydantic.Field(min_length=1, description="One-line change summary.")


@action(reads=[], writes=["stage", "service", "risk", "summary"])
def open_change(state: State, change: ChangeRequest) -> State:
    """Open a deployment change request.

    Args:
        change: A ``ChangeRequest`` object: ``{"service": str,
            "risk": "low" | "high", "summary": str}``. A dict that does not
            validate against that schema is refused as ``validation_failed``.
    """
    return state.update(
        stage="opened",
        service=change.service,
        risk=change.risk,
        summary=change.summary,
    )


@action(reads=["service", "risk"], writes=["stage", "review_notes"])
def review(state: State) -> State:
    """Review the open change. Branches to deploy / reject / abort."""
    risk = state["risk"]
    return state.update(
        stage="reviewed",
        review_notes=f"{state['service']} reviewed; risk={risk}",
    )


@action(reads=["stage"], writes=["stage", "reject_reason"])
def reject(state: State, reason: str) -> State:
    """Reject the reviewed change. Terminal.

    Args:
        reason: Why the change is rejected.
    """
    return state.update(stage="rejected", reject_reason=reason)


@action(reads=["stage"], writes=["stage", "deploy_reason"])
def deploy(state: State, reason: str = "") -> State:
    """Deploy the reviewed change. Signed-approval-gated.

    Refused unless a human has signed *this exact call* (same reason,
    same gate) with the approver's Ed25519 private key — an approval the
    agent cannot produce, fake, or reuse. The refusal is a structured
    ``validation_failed`` carrying the pending approval id.

    Args:
        reason: Non-empty deployment justification. Bound into the approval.
    """
    return state.update(stage="deployed", deploy_reason=reason)


@action(reads=["stage", "service"], writes=["stage", "verify_result"])
def verify(state: State) -> State:
    """Verify the deployment succeeded. Terminal."""
    return state.update(stage="verified", verify_result=f"{state['service']} healthy")


@action(reads=["stage"], writes=["stage"])
def rollback(state: State) -> State:
    """Roll the deployment back. Terminal; reachable after deploy."""
    return state.update(stage="rolled_back")


@action(reads=["stage"], writes=["stage"])
def abort(state: State) -> State:
    """Abort the change. Terminal; reachable pre-deploy."""
    return state.update(stage="aborted")


# ── The signed-approval gate ───────────────────────────────────────────────


def _state_dir() -> Path:
    """Where the demo keeps its approvals db and keypair."""
    return Path(os.environ.get("AUTHIRO_DEPLOY_STATE_DIR", str(Path.home() / ".authiro-deploy")))


def _demo_keys() -> tuple[Path, Path]:
    """Load (or generate once) the demo approver keypair.

    In production the private key lives with the human, never on the
    machine the agent can read; this demo keeps both files in one
    directory so the walkthrough runs without setup. The signature
    check is real either way: nothing short of the private key can
    turn a pending request into a consumable approval.
    """
    keys = _state_dir() / "keys"
    public = keys / "approver.pub"
    if not public.exists():
        generate_key_pair(keys)
    return keys / "approver.key", public


def _approval_store() -> ApprovalStore:
    """The gate-side store: configured with the public key only."""
    _, public = _demo_keys()
    return ApprovalStore(
        _state_dir() / "approvals.db",
        gate=_GATE_NAME,
        environment=_GATE_ENV,
        ttl=_APPROVAL_TTL,
        public_key_pem=public.read_bytes(),
    )


def human_approve(request_id: str) -> None:
    """Sign a pending request with the demo private key (the human's part).

    This is what the approver does out of band — in production via
    ``authiro approve <id>`` on their own machine, with a key the gate
    only ever sees the public half of.
    """
    private, _ = _demo_keys()
    store = ApprovalStore(
        _state_dir() / "approvals.db",
        gate=_GATE_NAME,
        environment=_GATE_ENV,
        ttl=_APPROVAL_TTL,
    )
    request = store.get(request_id)
    if request is None:
        raise KeyError(f"unknown approval request {request_id!r}")
    store.approve(request_id, sign_payload(private.read_bytes(), request.payload))


def _deploy_gate(state: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any] | None:
    """Escalation gate for ``deploy``: refuse without a signed human approval."""
    reason = str(inputs.get("reason") or "").strip()
    if not reason:
        raise ValidationFailed(
            "deploy refused: a non-empty 'reason' is required to deploy",
            details={"param": "reason", "requirement": "non-empty deployment justification"},
        )
    store = _approval_store()
    binding = {"reason": reason}
    call_hash = args_hash(binding)
    ok, _request, why = store.consume("deploy", call_hash)
    if ok:
        return None
    pending = store.get_or_create("deploy", call_hash, risk="destructive", args_redacted=binding)
    raise ValidationFailed(
        f"deploy refused: no signed human approval ({why})",
        details={
            "approval_id": pending.id,
            "how_to_approve": f"human_approve({pending.id!r})",
            "binding": "the approval signs this exact reason, expires in "
            f"{_APPROVAL_TTL}s, and is single-use",
        },
    )


deploy._authiro_validator = _deploy_gate  # type: ignore[attr-defined]


def build() -> ApplicationBuilder:
    """Return the unbuilt deploy-approval builder (the builder seam).

    Returns an ``ApplicationBuilder`` rather than a built ``Application`` so
    Authiro stamps a per-session ``app_id`` and binds the tracker dir to
    the session before building. Do not set your own ``app_id`` here.
    """
    reviewed = Condition.expr("stage == 'reviewed'")
    deployed = Condition.expr("stage == 'deployed'")
    return (
        ApplicationBuilder()
        .with_actions(
            open_change=open_change,
            review=review,
            reject=reject,
            deploy=deploy,
            verify=verify,
            rollback=rollback,
            abort=abort,
        )
        .with_transitions(
            ("open_change", "review", Condition.expr("stage == 'opened'")),
            ("review", "deploy", reviewed),
            ("review", "reject", reviewed),
            ("review", "abort", reviewed),
            ("deploy", "verify", deployed),
            ("deploy", "rollback", deployed),
        )
        .with_tracker(tracker(project=_TRACKER_PROJECT))
        .with_state(stage="new")
        .with_entrypoint("open_change")
    )
