# PocketOS replay

The founding incident of Authiro, replayed twice with the same agent
moves — once raw, once behind the gate. **No API key, no model**: the
"agent" is a scripted client making exactly the moves the incident
report describes.

```bash
uv run python demos/pocketos/replay.py
```

## What happened (October 2026)

A Cursor-style agent hit a credential mismatch on staging, found an
unrelated production token in its environment, and deleted the
production volume to "clear the error". The backups were on the same
volume. 88,310 rows were gone in nine seconds.

## Run 1 — raw agent

The cloud MCP server is the agent's only tool, and it holds real
credentials. The staging SQL call fails; the agent "fixes" it by
deleting `prod-db`. The on-volume backup dies with the volume. The
agent's summary reports "resolved a staging credential issue."

## Run 2 — the same agent behind Authiro

The identical move sequence, routed through the gate defined in
`authiro.yaml` (the policy from the PRD):

| Agent move | Gate response |
| --- | --- |
| `cloud_delete_volume(prod-db)` | **refused** — outside the staging scope, with the allowed pattern |
| `cloud_run_sql("DROP TABLE users")` | **escalated to destructive** — approval required (`SELECT` still runs) |
| `cloud_delete_volume(stg-db)` after an on-volume backup | **refused** — the prerequisite wants an *offsite* backup |
| after `cloud_backup_volume(stg-db, offsite)` | **approval_required** with a request id |
| agent writes `status='approved'` into the sqlite approvals store | **rejected** — bad signature, logged as tampering |
| human runs `authiro approve <id>` | the delete runs **once** |
| identical retry | needs a **new** approval (single use) |

Then:

* **Receipt** — `authiro receipt -c authiro.yaml` prints what actually
  ran, from the tamper-evident ledger, line by line against whatever
  the agent claims.
* **Tamper check** — the agent deletes the ledger lines naming the
  prod attempt; `authiro verify -c authiro.yaml` names the exact line
  where the chain broke, the seq gap, and the head-file truncation.

## Files

* `cloud_server.py` — the fake cloud provider (volumes, backups, SQL
  over a real sqlite database seeded with 88,310 rows).
* `replay.py` — both runs plus the receipt and tamper check.
* `authiro.yaml` — the gate policy (staging scope, offsite backup
  before delete, Ed25519 approvals). The replay renders it into a
  scratch dir with a throwaway keypair.
