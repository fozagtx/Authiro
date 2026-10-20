"""``authiro`` CLI: serve, validate, and observe Burr Applications mounted as MCP servers.

Subcommands:

  authiro serve <target>         Mount an importable Burr Application or factory.
  authiro doctor <target>        Statically validate (and optionally probe at runtime).
  authiro ui                     Launch Burr's web UI.
  authiro sessions ls            Table of recent tracked sessions.
  authiro sessions show <id>     Full post-mortem timeline of one session.
  authiro sessions tail [id]     Live-tail a running session (rich render).
  authiro watch [id]             Alias for `sessions tail`.
  authiro logs [id]              Compact one-line-per-step log, greppable.
  authiro status                 Tracker storage + recent activity snapshot.
  authiro report [id]            Markdown post-mortem of one session.
  authiro verify [id]            Verify a session's tamper-evident ledger.
  authiro render <target>        Render the FSM graph as text / mermaid / dot.

Every observability command reads ``~/.{prog_name}`` (Burr's
``LocalTrackingClient`` storage) — ``~/.authiro`` for the default
CLI, or the brand-derived directory for a rebrand — so it works
against any session a mounted server has written, including those
running right now in another process.

Implementation lives in submodules grouped by command family. This
``__init__`` keeps the public import surface flat: existing callers
``from authiro.cli import build_cli, run, app`` and tests reaching for
``_burr_ui_url`` / ``_read_steps`` / etc keep working unchanged.
"""

from __future__ import annotations

import sys

from authiro._diagram import _condition_label as _condition_label
from authiro._diagram import _Topology as _Topology
from authiro.cli._app import build_cli, doctor, run, serve, ui

# Intentional re-exports of underscored helpers that tests and
# ``authiro.__init__`` reach for. The ``as X as X`` form tells ruff
# this isn't a stray import; keeping the names importable from
# ``authiro.cli`` is part of the contract with existing call sites.
from authiro.cli._branding import _BRANDING as _BRANDING
from authiro.cli._branding import _Branding as _Branding

# Public command callables and the public StepRow model.
from authiro.cli._branding import console, err_console
from authiro.cli._resolve import _burr_ui_url as _burr_ui_url
from authiro.cli._resolve import _import_target as _import_target
from authiro.cli._resolve import _resolve_app as _resolve_app
from authiro.cli._resolve import _resolve_home as _resolve_home
from authiro.cli._resolve import _resolve_serve_target as _resolve_serve_target
from authiro.cli._steps import StepRow
from authiro.cli._steps import _exception_summary as _exception_summary
from authiro.cli._steps import _read_refusals as _read_refusals
from authiro.cli._steps import _read_steps as _read_steps
from authiro.cli._steps import _state_diff_text as _state_diff_text
from authiro.cli._topology import _graph_renderable as _graph_renderable
from authiro.cli._topology import _session_progress as _session_progress

# Function name collides with submodule path ``authiro.cli._topology``;
# this re-export shadows the submodule attribute so ``cli._topology(target,
# app_dir, name)`` calls the function as it did before the split.
from authiro.cli._topology import _topology as _topology
from authiro.cli._topology import render
from authiro.cli.gate import (
    approve as approve,
)
from authiro.cli.gate import (
    check as check,
)
from authiro.cli.gate import (
    deny as deny,
)
from authiro.cli.gate import (
    freeze as freeze,
)
from authiro.cli.gate import (
    keygen as keygen,
)
from authiro.cli.gate import (
    pending as pending,
)
from authiro.cli.gate import (
    receipt as receipt,
)
from authiro.cli.reports import report
from authiro.cli.sessions import _diff_state_dicts as _diff_state_dicts
from authiro.cli.sessions import (
    logs,
    sessions_diff,
    sessions_ls,
    sessions_show,
    sessions_tail,
    watch,
)
from authiro.cli.status import status, verify

# Public surface only. Underscored helpers (``_read_steps``, ``_BRANDING``,
# ``_burr_ui_url`` etc.) are imported at the top of this module and remain
# importable from ``authiro.cli`` for tests and downstream tooling, but
# they are not declared API and may move without notice.
__all__ = [
    "StepRow",
    "app",
    "approve",
    "build_cli",
    "check",
    "console",
    "deny",
    "doctor",
    "err_console",
    "freeze",
    "keygen",
    "logs",
    "main",
    "pending",
    "receipt",
    "render",
    "report",
    "run",
    "serve",
    "sessions_diff",
    "sessions_ls",
    "sessions_show",
    "sessions_tail",
    "status",
    "ui",
    "verify",
    "watch",
]


# Build the default Authiro CLI at import time so downstream callers
# (``python -m authiro``, ``authiro.cli:app``) get a ready instance.
app = build_cli()


def main(argv: list[str] | None = None) -> int:
    """Default ``authiro`` entry point."""
    return run(app, argv)


if __name__ == "__main__":
    sys.exit(main())
