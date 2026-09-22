# JIT access — grant lifecycle

The broker replaces standing production access with time-bound grants.

```
                 request_access                 approve (actor != requester)
   subject ─────────────────────►  PENDING  ─────────────────────────────►  APPROVED
                                      │  │                                     │  │
                                deny │  │ (auto-approve for                    │  │ revoke
                                      ▼  │  low-risk roles)                     │  ▼
                                   DENIED │                                     │ REVOKED
                                          ▼                                     │
                                       APPROVED ◄───────────────────────────────┘
                                          │
                                    ttl elapses (lazy check)
                                          ▼
                                       EXPIRED
```

## Rules

- **Role TTL ceilings** (`ROLE_MAX_TTL`): the requested TTL is capped per role —
  `phi_reader` ≤ 8h, `phi_operator` ≤ 1h, `db_admin` ≤ 30m, `break_glass` ≤ 15m.
- **Approval-required roles** (`ROLES_REQUIRING_APPROVAL`): privileged roles start
  `PENDING` and need a second principal; low-risk roles (`phi_reader`)
  auto-activate under policy.
- **Separation of duties**: the approver must differ from the requester.
- **Substantive justification**: required (≥ 8 chars), captured in the audit log.
- **Auto-expiry**: grants past `expires_at` are marked `EXPIRED` on the next read
  (`_expire_due`), so `is_active()` and `active_grant_for()` are always current.

## Access decision

`check_access()` fuses RBAC and ABAC:

1. Look up an **active grant** for `(subject, resource)`.
2. Inject `jit_grant_active` (and the grant's role) into the ABAC context.
3. Delegate the final allow/deny to the ABAC engine, which weighs data
   sensitivity, MFA, and network tier.

So a PHI export is denied by default and only permitted while a valid, approved,
unexpired grant exists — after which access silently reverts to denied with no
code change or manual cleanup.

## Try it

```bash
make serve      # then open http://127.0.0.1:8000/docs
```

```bash
# request
curl -sX POST localhost:8000/grants -H 'content-type: application/json' -d '{
  "subject_id":"alice@ih.com","role":"phi_operator",
  "target_resource":"arn:aws:s3:::ih-phi-exports-prod",
  "justification":"Investigating INC-4821","requested_ttl":900}'

# approve (as a different principal)
curl -sX POST localhost:8000/grants/<id>/approve -H 'X-Actor: bob@ih.com'

# check access
curl -sX POST localhost:8000/access/check -H 'content-type: application/json' -d '{
  "subject_id":"alice@ih.com","roles":["phi_operator"],
  "resource_id":"arn:aws:s3:::ih-phi-exports-prod",
  "sensitivity":"phi","action":"export",
  "context":{"mfa":true,"network_tier":"corp"}}'
```
