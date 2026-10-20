"""Signed human approvals for destructive calls.

The gate can never produce an approval: it holds only the approver's
**public** key. A human with the private key runs ``authiro approve
<id>`` out of band; the CLI signs the request's canonical payload and
records the signature. When the gate later sees the identical call, it
verifies the signature against the public key before consuming the
approval.

What each attack buys the agent, and why it fails:

* **Editing the sqlite row** to ``status='approved'`` — the stored
  signature is either absent or does not verify against the public
  key, so the gate refuses the call and logs the attempt.
* **Replaying a consumed approval** — consumption is a single atomic
  ``UPDATE ... WHERE status='approved'``; the second caller updates zero
  rows and is refused.
* **Replaying an approval against different arguments** — the payload
  binds ``(id, gate, environment, tool, args_hash)``; a mismatched call
  never looks the row up by id.
* **Waiting out the human** — approvals expire (default 15 minutes
  from signing).
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
CONSUMED = "consumed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approval_requests (
    id TEXT PRIMARY KEY,
    gate TEXT NOT NULL,
    environment TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_redacted TEXT NOT NULL,
    risk TEXT NOT NULL DEFAULT 'destructive',
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    signature TEXT,
    created_at REAL NOT NULL,
    approved_at REAL,
    expires_at REAL,
    consumed_at REAL,
    denied_at REAL
);
CREATE INDEX IF NOT EXISTS idx_approval_tool_args
    ON approval_requests (tool, args_hash, environment, status);
"""


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class ApprovalRequest:
    """One pending or resolved approval request.

    ``payload`` is the canonical JSON the human signs: it binds the
    request id, the gate, the environment, the tool, and the args hash.
    ``args_redacted`` is the display copy (secrets masked) shown by
    ``authiro pending`` and the approval prompt.
    """

    id: str
    gate: str
    environment: str
    tool: str
    args_hash: str
    args_redacted: dict[str, Any]
    risk: str
    payload: str
    status: str
    created_at: float
    approved_at: float | None = None
    expires_at: float | None = None
    signature: str | None = None

    @property
    def expired(self) -> bool:
        """Whether an approved request has passed its expiry."""
        return (
            self.status == APPROVED
            and self.expires_at is not None
            and time.time() >= (self.expires_at)
        )

    def effective_status(self) -> str:
        """The status an approver should see (approved past TTL is expired)."""
        if self.expired:
            return "expired"
        return self.status

    def to_dict(self) -> dict[str, Any]:
        """The wire shape shown by ``authiro pending`` and approval prompts."""
        return {
            "id": self.id,
            "gate": self.gate,
            "environment": self.environment,
            "tool": self.tool,
            "args": self.args_redacted,
            "risk": self.risk,
            "status": self.effective_status(),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


def generate_key_pair(out_dir: str | Path, *, prefix: str = "approver") -> tuple[Path, Path]:
    """Generate an Ed25519 keypair for signing approvals.

    Writes ``{prefix}.key`` (private, mode 0600) and ``{prefix}.pub``
    (public). Returns ``(private_path, public_path)``. The private key
    stays with the human; only the public key is configured on the gate.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_path = out / f"{prefix}.key"
    public_path = out / f"{prefix}.pub"
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def sign_payload(private_key_pem: bytes, payload: str) -> str:
    """Sign ``payload`` (canonical JSON text) with an Ed25519 private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the private key file is not an Ed25519 key")
    raw = key.sign(payload.encode("utf-8"))
    return base64.b64encode(raw).decode("ascii")


def verify_signature(public_key_pem: bytes, payload: str, signature_b64: str) -> bool:
    """Verify a base64 Ed25519 signature over ``payload``; never raises."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(base64.b64decode(signature_b64), payload.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class ApprovalStore:
    """Sqlite-backed approval requests for one gate.

    The gate process and the ``authiro approve`` CLI are different
    processes against the same file; sqlite handles that. The gate
    configures the store with the **public** key only. The approve CLI
    constructs its own store handle (no public key needed for signing;
    it never gets to mark a row consumed).
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        gate: str,
        environment: str,
        ttl: int = 900,
        public_key_pem: bytes | None = None,
    ) -> None:
        """Open (or create) the requests database; see the class docstring."""
        self._path = Path(db_path)
        self._gate = gate
        self._environment = environment
        self._ttl = ttl
        self._public_key = public_key_pem
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    @property
    def db_path(self) -> Path:
        """Path of the backing sqlite file."""
        return self._path

    # ── Gate side ──────────────────────────────────────────────────────────

    def get_or_create(
        self,
        tool: str,
        args_hash: str,
        *,
        risk: str,
        args_redacted: Mapping[str, Any] | None = None,
    ) -> ApprovalRequest:
        """Find (or file) the pending request for this exact call.

        Retrying the identical destructive call while it waits for a
        human returns the *same* request id, so one approval covers the
        retry. Once consumed, a retry files a fresh request — approvals
        are single-use.
        """
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE tool=? AND args_hash=? AND "
                "environment=? AND gate=? AND status=? ORDER BY created_at DESC LIMIT 1",
                (tool, args_hash, self._environment, self._gate, PENDING),
            ).fetchone()
            if row is not None:
                return self._row_to_request(row)
            request_id = uuid.uuid4().hex[:12]
            payload = _canonical(
                {
                    "id": request_id,
                    "gate": self._gate,
                    "environment": self._environment,
                    "tool": tool,
                    "args_hash": args_hash,
                }
            )
            display = dict(args_redacted if args_redacted is not None else {})
            conn.execute(
                "INSERT INTO approval_requests (id, gate, environment, tool, args_hash, "
                "args_redacted, risk, payload, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    self._gate,
                    self._environment,
                    tool,
                    args_hash,
                    _canonical(display),
                    risk,
                    payload,
                    PENDING,
                    now,
                ),
            )
            return ApprovalRequest(
                id=request_id,
                gate=self._gate,
                environment=self._environment,
                tool=tool,
                args_hash=args_hash,
                args_redacted=display,
                risk=risk,
                payload=payload,
                status=PENDING,
                created_at=now,
            )

    def has_valid_approval(self, tool: str, args_hash: str) -> bool:
        """Whether a signed, unexpired, unconsumed approval matches this call.

        Signature verification happens here, on read, so a row edited
        directly in sqlite (status flipped to ``approved`` without a
        valid signature) is rejected. Consumption happens atomically in
        :meth:`consume`.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE tool=? AND args_hash=? AND "
                "environment=? AND gate=? AND status=? ORDER BY approved_at DESC",
                (tool, args_hash, self._environment, self._gate, APPROVED),
            ).fetchall()
        for row in rows:
            request = self._row_to_request(row)
            if request.expired:
                continue
            if not self._verifies(request):
                continue
            return True
        return False

    def consume(self, tool: str, args_hash: str) -> tuple[bool, ApprovalRequest | None, str]:
        """Atomically consume the valid approval for this exact call.

        Returns ``(ok, request, why)``. ``ok`` is True exactly once per
        approval: the ``UPDATE ... WHERE status='approved'`` guards the
        race between two concurrent retries. Rows whose signature does
        not verify (or that expired) are skipped in favor of a valid
        one; a store with no usable row reports why — a row that
        reached ``approved`` without a verifying signature is refused
        here and the reason is returned for the ledger.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE tool=? AND args_hash=? AND "
                "environment=? AND gate=? AND status=? ORDER BY approved_at DESC",
                (tool, args_hash, self._environment, self._gate, APPROVED),
            ).fetchall()
        if not rows:
            return False, None, "no approved request for this call"
        for row in rows:
            request = self._row_to_request(row)
            if request.expired or not self._verifies(request):
                continue
            with self._lock, self._connect() as conn:
                cur = conn.execute(
                    "UPDATE approval_requests SET status=?, consumed_at=? WHERE id=? AND status=?",
                    (CONSUMED, time.time(), request.id, APPROVED),
                )
                if cur.rowcount != 1:
                    continue  # a racing retry consumed it first
            from dataclasses import replace

            return True, replace(request, status=CONSUMED), "consumed"
        newest = self._row_to_request(rows[0])
        if newest.expired:
            return False, newest, "approval expired"
        return False, newest, "signature failed verification (forged or corrupted row)"

    def _verifies(self, request: ApprovalRequest) -> bool:
        """Re-verify the stored signature against the configured public key."""
        if self._public_key is None or not request.signature:
            return False
        return verify_signature(self._public_key, request.payload, request.signature)

    # ── Human side ─────────────────────────────────────────────────────────

    def approve(self, request_id: str, signature_b64: str) -> ApprovalRequest:
        """Record a human's signature on a pending request.

        The gate-side store (configured with the public key) verifies
        signatures on read, so this method does not: it belongs to the
        ``authiro approve`` CLI, which signs with the private key.
        """
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown approval request {request_id!r}")
            if row["status"] != PENDING:
                raise ValueError(f"request {request_id} is {row['status']}, not pending")
            conn.execute(
                "UPDATE approval_requests SET status=?, signature=?, approved_at=?, "
                "expires_at=? WHERE id=? AND status=?",
                (APPROVED, signature_b64, now, now + self._ttl, request_id, PENDING),
            )
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)
            ).fetchone()
            request = self._row_to_request(row)
        assert request is not None
        return request

    def deny(self, request_id: str) -> ApprovalRequest:
        """Mark a pending request denied by the human."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown approval request {request_id!r}")
            if row["status"] not in (PENDING, APPROVED):
                raise ValueError(f"request {request_id} is {row['status']}")
            conn.execute(
                "UPDATE approval_requests SET status=?, denied_at=? WHERE id=?",
                (DENIED, time.time(), request_id),
            )
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)
            ).fetchone()
            request = self._row_to_request(row)
        assert request is not None
        return request

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Fetch one request by id, whatever its status."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)
            ).fetchone()
        return self._row_to_request(row) if row is not None else None

    def pending(self) -> list[ApprovalRequest]:
        """All pending requests, oldest first (what ``authiro pending`` shows)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE status=? ORDER BY created_at",
                (PENDING,),
            ).fetchall()
        return [self._row_to_request(r) for r in rows]

    @staticmethod
    def _row_to_request(row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            id=row["id"],
            gate=row["gate"],
            environment=row["environment"],
            tool=row["tool"],
            args_hash=row["args_hash"],
            args_redacted=json.loads(row["args_redacted"]),
            risk=row["risk"],
            payload=row["payload"],
            status=row["status"],
            created_at=row["created_at"],
            approved_at=row["approved_at"],
            expires_at=row["expires_at"],
            signature=row["signature"],
        )
