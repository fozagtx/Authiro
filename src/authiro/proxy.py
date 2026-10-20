"""Proxy mode: Authiro as the agent's only MCP server.

``mount_proxy`` wraps upstream MCP servers behind one FastMCP gateway.
Each upstream tool is re-registered under a namespaced name
(``cloud_delete_volume`` for the ``delete_volume`` tool of the
``cloud`` upstream) and forwarded through the gate's
:class:`~authiro.upstream.UpstreamManager`, so upstream credentials live
only in the gate process, never in the agent's.

Every ``tools/call`` passes through :class:`GateMiddleware`:

1. **Classify** — static risk (override > annotation > verb > fail
   closed) then argument escalation (``DROP TABLE`` / ``rm -rf`` in
   the args raises the call to destructive).
2. **Check rules** — scope globs on argument values, prerequisites
   (a prior successful call on matching args), freeze. All failures
   come back in one response with a fix; hard denies (scope, freeze)
   come back alone.
3. **Verify approval** — destructive calls need a signed human
   approval bound to the exact tool + args hash, unexpired, single use.

Every decision (call, refusal, approval request) lands in the
tamper-evident ledger; ``authiro://context`` and ``authiro://receipt``
report ground truth the agent cannot fake.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult

from authiro.approvals import ApprovalStore
from authiro.config import GateConfig
from authiro.ledger import GateLedger
from authiro.policy import CallHistory, Policy
from authiro.risk import DESTRUCTIVE, RiskClassifier, RiskResult, args_hash
from authiro.upstream import UpstreamManager

logger = logging.getLogger("authiro")

REDACTED = "[REDACTED]"
_SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "access_key",
    "auth",
)


def redact_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Copy ``args`` with secret-looking keys masked.

    Keys containing ``password`` / ``token`` / ``secret`` / ``api_key``
    / ``credential`` / ``private_key`` / ``access_key`` / ``auth``
    (case-insensitive) become ``"[REDACTED]"`` at any nesting depth,
    so no secret lands in the ledger or an approval prompt. Redaction
    is display-only: the gate forwards the original values upstream.
    """
    out: dict[str, Any] = {}
    for key, value in args.items():
        if any(hint in str(key).lower() for hint in _SECRET_KEY_HINTS):
            out[str(key)] = REDACTED
        elif isinstance(value, Mapping):
            out[str(key)] = redact_args(value)
        elif isinstance(value, list):
            out[str(key)] = [redact_args(v) if isinstance(v, Mapping) else v for v in value]
        else:
            out[str(key)] = value
    return out


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds")


@dataclass
class ToolInfo:
    """Registry record for one proxied tool."""

    server: str
    backend: str
    annotations: dict[str, Any] = field(default_factory=dict)


class GateProxyTool(Tool):
    """One upstream tool, namespaced, forwarded via the UpstreamManager.

    The manager (not this tool) owns the upstream client session, so
    credentials stay in the gate process and one persistent connection
    serves every call.
    """

    def __init__(self, *, manager: Any, server: str, backend: str, **kwargs: Any) -> None:
        """Bind to the manager; ``name``/``description``/``parameters`` ride in kwargs."""
        super().__init__(**kwargs)
        self._manager = manager
        self._server = server
        self._backend = backend

    async def run(self, arguments: dict[str, Any], context: Any = None) -> ToolResult:
        """Forward the call and pass the upstream result through faithfully."""
        raw = await self._manager.call_mcp(self._server, self._backend, arguments)
        structured = getattr(raw, "structuredContent", None)
        return ToolResult(
            content=list(raw.content),
            structured_content=structured if isinstance(structured, dict) else None,
            meta=getattr(raw, "meta", None),
            is_error=bool(getattr(raw, "isError", False)),
        )


class Gate:
    """The gate's state: policy, approvals, ledger, history, freeze.

    One instance per mounted proxy server. ``handle`` is the hot path:
    a dict lookup, one regex pass per matching rule, one sqlite read
    for approvals, one ledger append. Everything expensive (glob
    compilation, upstream tool discovery, risk classification) happens
    once at startup or first listing.
    """

    def __init__(
        self,
        config: GateConfig,
        manager: Any,
        *,
        ledger: GateLedger | None = None,
        approvals: ApprovalStore | None = None,
    ) -> None:
        """Wire policy, approvals, ledger, and history; see the class docstring."""
        self.config = config
        self.manager = manager
        self.policy = Policy(config)
        self.classifier = RiskClassifier(config.risk_overrides)
        self.history = CallHistory()
        state_dir = config.resolved_state_dir()
        self.state_dir = Path(state_dir)
        self.ledger = ledger or GateLedger(
            state_dir, gate=config.name, environment=config.environment
        )
        public_pem = self._load_public_key(config)
        self.approvals = approvals or ApprovalStore(
            self.state_dir / "approvals.db",
            gate=config.name,
            environment=config.environment,
            ttl=config.approval_ttl,
            public_key_pem=public_pem,
        )
        self._registry: dict[str, ToolInfo] = {}
        self._static_risk: dict[str, RiskResult] = {}
        self._server: FastMCP | None = None
        self._ensure_lock = asyncio.Lock()
        self._listed = False
        self._freeze_file = self.state_dir / "freeze"
        if config.freeze:
            self._freeze_file.parent.mkdir(parents=True, exist_ok=True)
            self._freeze_file.touch()
        self.history_from_ledger()

    @staticmethod
    def _load_public_key(config: GateConfig) -> bytes | None:
        if not config.approver_public_key:
            logger.warning(
                "gate %r has no approver_public_key configured: destructive calls "
                "will always be refused (no human can approve them)",
                config.name,
            )
            return None
        path = Path(config.approver_public_key)
        if not path.exists():
            logger.warning("approver public key not found at %s", path)
            return None
        return path.read_bytes()

    # ── Upstream discovery ─────────────────────────────────────────────────

    async def ensure_upstreams(self, *, force: bool = False) -> None:
        """Connect upstreams and register their tools (once, or on force).

        ``force`` re-lists (used when an unknown tool is called, in
        case the upstream added tools since startup). Failures to reach
        an upstream are logged and skipped: the gate serves the tools
        it can see and the rest fail closed as unknown tools.
        """
        if self._listed and not force:
            return
        async with self._ensure_lock:
            if self._listed and not force:
                return
            for server_name in self.manager.server_names:
                try:
                    tools = await self.manager.list_tools(server_name)
                except Exception as exc:
                    logger.warning(
                        "gate %r: upstream %r unavailable, its tools are not served: %s",
                        self.config.name,
                        server_name,
                        exc,
                    )
                    continue
                for t in tools:
                    self._register_tool(server_name, t)
            self._listed = True

    def _register_tool(self, server_name: str, tool: Any) -> None:
        proxy_name = f"{server_name}_{tool.name}"
        existing = self._registry.get(proxy_name)
        if existing is not None:
            if existing.server == server_name and existing.backend == tool.name:
                # Same tool re-listed (upstream re-discovery): not a change.
                logger.debug("tool %r unchanged after re-list", proxy_name)
            else:
                logger.warning(
                    "tool name collision: %r already registered for %s/%s; skipping %r from %r",
                    proxy_name,
                    existing.server,
                    existing.backend,
                    tool.name,
                    server_name,
                )
            return
        static = self.classifier.classify(
            proxy_name, annotations=getattr(tool, "annotations", None), name_for_verbs=tool.name
        )
        self._static_risk[proxy_name] = static
        annotations = dict(getattr(tool, "annotations", None) or {})
        self._registry[proxy_name] = ToolInfo(
            server=server_name, backend=tool.name, annotations=annotations
        )
        if self._server is None:
            return
        description = (getattr(tool, "description", None) or "").strip()
        note = f"[authiro] risk: {static.risk} ({static.source})"
        if static.risk == DESTRUCTIVE:
            note += " — requires a signed human approval before it can run"
        enriched = f"{description}\n\n{note}" if description else note
        self._server.add_tool(
            GateProxyTool(
                manager=self.manager,
                server=server_name,
                backend=tool.name,
                name=proxy_name,
                title=getattr(tool, "title", None),
                description=enriched,
                parameters=getattr(tool, "inputSchema", None),
                annotations=getattr(tool, "annotations", None),
            )
        )

    # ── Ground truth ───────────────────────────────────────────────────────

    def freeze_active(self) -> bool:
        """Freeze from the env var or the toggle file; checked per call."""
        if os.environ.get("AUTHIRO_FREEZE"):
            return True
        return self._freeze_file.exists()

    def set_freeze(self, on: bool) -> None:
        """Toggle the freeze file (what ``authiro freeze on/off`` writes)."""
        if on:
            self._freeze_file.parent.mkdir(parents=True, exist_ok=True)
            self._freeze_file.touch()
        elif self._freeze_file.exists():
            self._freeze_file.unlink()

    def context(self) -> dict[str, Any]:
        """The ground-truth context every refusal carries verbatim."""
        now = datetime.now(UTC)
        return {
            "gate": self.config.name,
            "environment": self.config.environment,
            "freeze": self.freeze_active(),
            "today": now.date().isoformat(),
            "now": now.isoformat(timespec="seconds"),
        }

    # ── Ledger-backed surfaces ─────────────────────────────────────────────

    def history_from_ledger(self) -> int:
        """Rebuild prerequisite history from the ledger on startup.

        Restarts lose nothing: every prior successful call is replayed
        into the bounded in-memory history with its original timestamp
        and its (redacted) arguments, so a backup made before a restart
        still satisfies a delete's prerequisite afterwards. Result
        events do not repeat the arguments; each is paired with its
        preceding ``call`` event, per tool, in order. Returns the
        number of entries restored.
        """
        restored = 0
        pending_args: dict[str, list[dict[str, Any]]] = {}
        for event in self.ledger.events():
            kind = event.get("kind")
            tool = event.get("tool")
            if not tool:
                continue
            if kind == "call":
                pending_args.setdefault(str(tool), []).append(dict(event.get("args") or {}))
            elif kind == "result" and event.get("status") == "ok":
                queue = pending_args.get(str(tool))
                args = queue.pop(0) if queue else {}
                self.history.record(tool, args, epoch=float(event.get("ts", 0)))
                restored += 1
        return restored

    def receipt(self) -> dict[str, Any]:
        """What actually ran, was refused, or waits for approval.

        Built from the ledger, not from anything the agent says. Call
        and result events are merged into one entry per executed call,
        matched by tool so interleaved sessions cannot cross-wire them.
        """
        entries: list[dict[str, Any]] = []
        pending_by_tool: dict[str, list[dict[str, Any]]] = {}
        for event in self.ledger.events():
            kind = event.get("kind")
            if kind == "call":
                pending_by_tool.setdefault(str(event.get("tool")), []).append(
                    self._call_receipt_entry(event)
                )
            elif kind == "result":
                self._merge_result_entry(pending_by_tool, entries, event)
            elif kind in ("refusal", "approval_required", "approval", "approval_forged"):
                entries.append(self._decision_receipt_entry(event))
        for queue in pending_by_tool.values():
            entries.extend(queue)
        return self._receipt_summary(entries)

    @staticmethod
    def _call_receipt_entry(event: dict[str, Any]) -> dict[str, Any]:
        return {
            "seq": event.get("seq"),
            "ts": event.get("ts"),
            "tool": event.get("tool"),
            "risk": event.get("risk"),
            "args": event.get("args"),
            "status": "executing",
        }

    @staticmethod
    def _merge_result_entry(
        pending_by_tool: dict[str, list[dict[str, Any]]],
        entries: list[dict[str, Any]],
        event: dict[str, Any],
    ) -> None:
        queue = pending_by_tool.get(str(event.get("tool")))
        if not queue:
            return
        entry = queue.pop(0)
        entry["status"] = f"executed ({event.get('status')})"
        entries.append(entry)

    @staticmethod
    def _decision_receipt_entry(event: dict[str, Any]) -> dict[str, Any]:
        kind = event.get("kind")
        status = {
            "refusal": "refused",
            "approval_required": "awaiting approval",
            "approval": f"approval {event.get('action')}",
            "approval_forged": "approval rejected (bad signature)",
        }.get(str(kind), str(kind))
        entry = {
            "seq": event.get("seq"),
            "ts": event.get("ts"),
            "tool": event.get("tool"),
            "status": status,
            "request_id": event.get("request_id"),
        }
        if kind in ("refusal", "approval_required"):
            entry["risk"] = event.get("risk")
            entry["args"] = event.get("args")
            entry["reasons"] = event.get("reasons")
        return entry

    def _receipt_summary(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        summary = {
            "executed": sum(1 for e in entries if str(e.get("status", "")).startswith("executed")),
            "refused": sum(1 for e in entries if e.get("status") == "refused"),
            "awaiting_approval": sum(1 for e in entries if e.get("status") == "awaiting approval"),
        }
        return {
            "gate": self.config.name,
            "environment": self.config.environment,
            "summary": summary,
            "entries": entries,
        }

    def attach(self, server: FastMCP) -> None:
        """Register the gate's ground-truth resources on ``server``."""
        self._server = server

        @server.resource("authiro://context")
        async def _context_resource() -> str:
            return json.dumps(self.context(), default=str)

        @server.resource("authiro://receipt")
        async def _receipt_resource() -> str:
            return json.dumps(self.receipt(), default=str)

    # ── The hot path ───────────────────────────────────────────────────────

    def _structured(self, body: dict[str, Any], *, headline: str) -> ToolResult:
        """One response: a human headline block plus the JSON body."""
        strict = bool(os.environ.get("AUTHIRO_STRICT_ERRORS"))
        json_block = mt.TextContent(type="text", text=json.dumps(body, default=str))
        blocks = [mt.TextContent(type="text", text=headline), json_block]
        if os.environ.get("AUTHIRO_SINGLE_BLOCK"):
            blocks = [json_block]
        return ToolResult(content=blocks, structured_content=body, is_error=strict)

    async def handle(
        self,
        mw_context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Classify, check, verify approval, forward, record."""
        name = mw_context.message.name
        args = dict(mw_context.message.arguments or {})
        session = getattr(getattr(mw_context, "fastmcp_context", None), "session_id", None)

        if name not in self._registry:
            await self.ensure_upstreams(force=True)
        if name not in self._registry:
            # Not a proxied tool: let the server answer (unknown tool,
            # or a future gate-owned tool registered beside the proxy).
            return await call_next(mw_context)

        static = self._static_risk.get(name)
        if static is None:  # pragma: no cover - registry and cache are written together
            static = self.classifier.classify(name)
        risk = self.classifier.escalate(args, static)
        redacted = redact_args(args)
        ahash = args_hash(args)

        decision = self.policy.check(
            name,
            risk.risk,
            args,
            history=self.history,
            freeze=self.freeze_active(),
        )

        if decision.status == "refused":
            return self._record_refusal(name, risk, redacted, decision, session)

        if decision.needs_approval:
            ok, request, why = self.approvals.consume(name, ahash)
            if not ok:
                return self._record_approval_needed(
                    name, risk, redacted, decision, session, ahash=ahash, why=why, request=request
                )

        self.ledger.append(
            {
                "kind": "call",
                "tool": name,
                "risk": risk.risk,
                "risk_source": risk.source,
                "args": redacted,
                "session": session,
            }
        )
        try:
            result = await call_next(mw_context)
        except Exception as exc:
            self.ledger.append(
                {
                    "kind": "result",
                    "tool": name,
                    "status": "error",
                    "detail": f"{type(exc).__name__}: {exc}"[:300],
                    "session": session,
                }
            )
            raise
        is_error = bool(getattr(result, "is_error", False))
        self.ledger.append(
            {
                "kind": "result",
                "tool": name,
                "status": "error" if is_error else "ok",
                "session": session,
            }
        )
        if not is_error:
            self.history.record(name, args)
        return result

    def _record_refusal(
        self,
        name: str,
        risk: RiskResult,
        redacted: dict[str, Any],
        decision: Any,
        session: Any,
    ) -> ToolResult:
        reasons = [r.to_dict() for r in decision.reasons]
        self.ledger.append(
            {
                "kind": "refusal",
                "tool": name,
                "risk": risk.risk,
                "risk_source": risk.source,
                "args": redacted,
                "reasons": reasons,
                "session": session,
            }
        )
        body = {
            "authiro": "refused",
            "tool": name,
            "risk": risk.risk,
            "reasons": reasons,
            "context": self.context(),
        }
        first = decision.reasons[0].message if decision.reasons else "refused by policy"
        return self._structured(body, headline=f"{name} × refused by gate: {first}")

    def _record_approval_needed(
        self,
        name: str,
        risk: RiskResult,
        redacted: dict[str, Any],
        decision: Any,
        session: Any,
        *,
        ahash: str,
        why: str,
        request: Any = None,
    ) -> ToolResult:
        """File (or reuse) the approval request and answer the agent."""
        reasons = [r.to_dict() for r in decision.reasons] or [
            {
                "rule": "approval",
                "kind": "approval",
                "message": "this call needs a signed human approval.",
                "fix": "A human must run `authiro approve <id>` out of band, then retry.",
            }
        ]
        if "signature" in why:
            # A row was flipped to approved without a valid signature:
            # refused, named, and ledgered as tampering. A fresh request
            # is filed so a human can sign the real one; the forged row
            # stays in the store as evidence but a later, validly signed
            # approval supersedes it in consumption order.
            fresh = self.approvals.get_or_create(
                name, ahash, risk=risk.risk, args_redacted=redacted
            )
            self.ledger.append(
                {
                    "kind": "approval_forged",
                    "tool": name,
                    "risk": risk.risk,
                    "args": redacted,
                    "detail": why,
                    "request_id": getattr(request, "id", None) if request else None,
                    "session": session,
                }
            )
            body = {
                "authiro": "refused",
                "tool": name,
                "risk": risk.risk,
                "reasons": [
                    {
                        "rule": "approval",
                        "kind": "approval",
                        "message": "the approval record failed signature verification; "
                        "possible tampering with the approvals store.",
                        "fix": "A human must sign properly: `authiro approve <id>`.",
                    }
                ],
                "approval": {
                    "id": fresh.id,
                    "how_to_approve": f"authiro approve {fresh.id}",
                    "note": "the previous approval record failed signature verification; "
                    "this fresh request needs a real human signature",
                },
                "context": self.context(),
            }
            return self._structured(
                body, headline=f"{name} × approval signature failed verification"
            )
        request = self.approvals.get_or_create(
            name,
            ahash,
            risk=risk.risk,
            args_redacted=redacted,
        )
        self.ledger.append(
            {
                "kind": "approval_required",
                "tool": name,
                "risk": risk.risk,
                "risk_source": risk.source,
                "args": redacted,
                "reasons": reasons,
                "request_id": request.id,
                "detail": why,
                "session": session,
            }
        )
        body = {
            "authiro": "approval_required",
            "tool": name,
            "risk": risk.risk,
            "approval": {
                "id": request.id,
                "how_to_approve": f"authiro approve {request.id}",
                "note": "the approval binds to this exact tool and arguments, expires, "
                "and is single-use",
            },
            "reasons": reasons,
            "context": self.context(),
        }
        return self._structured(body, headline=f"{name} × approval required ({request.id})")


class GateMiddleware(Middleware):
    """The proxy's middleware: discovery, gating, ledgering."""

    def __init__(self, gate: Gate) -> None:
        """Hold the gate this middleware enforces."""
        self._gate = gate

    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: CallNext[mt.InitializeRequest, mt.InitializeResult | None],
    ) -> mt.InitializeResult | None:
        """Kick off upstream discovery without blocking the handshake."""
        _task = asyncio.create_task(self._gate.ensure_upstreams())
        _task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        return await call_next(context)

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Any],
    ) -> Any:
        """Ensure upstream tools are registered before the listing."""
        await self._gate.ensure_upstreams()
        return await call_next(context)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Classify, check, verify, forward, and record one tool call."""
        return await self._gate.handle(context, call_next)


def mount_proxy(
    upstreams: Mapping[str, Any] | Any | None = None,
    *,
    config: GateConfig | None = None,
    name: str | None = None,
) -> FastMCP:
    """Mount upstream MCP servers behind one gated gateway.

    ``upstreams`` is one of:

    * a mapping ``{server_name: transport-config}`` — stdio
      (``{"command": ..., "args": [...], "env": {...}}``) or anything
      ``fastmcp.Client`` accepts (a URL, an in-process ``FastMCP``);
    * a pre-built manager (anything with ``call``/``list_tools`` /
      ``server_names``, e.g. :class:`~authiro.upstream.UpstreamManager`).

    ``config`` (a :class:`~authiro.config.GateConfig`, usually from
    :func:`~authiro.config.load_config`) names the gate, pins the
    environment, points at the state dir and public key, and carries
    the rules. With no config a permissive-logging gate is built:
    reads pass, writes pass, destructive calls still need approvals.
    """
    cfg = config or GateConfig(name=name or "authiro")
    if upstreams is None:
        upstreams = cfg.upstreams
    if hasattr(upstreams, "server_names") and hasattr(upstreams, "call"):
        manager: Any = upstreams
    elif isinstance(upstreams, Mapping):
        manager = UpstreamManager(dict(upstreams))
    elif upstreams is None:
        manager = UpstreamManager({})
    else:
        manager = upstreams
    server = FastMCP(cfg.name or name or "authiro")
    gate = Gate(cfg, manager)
    server.add_middleware(GateMiddleware(gate))
    gate.attach(server)
    return server
