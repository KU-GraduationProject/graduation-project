# Application admin API executor contract

Source requirements: [Remediation proposal](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85), sections 7.4–7.6.

`AppApiExecutor` performs real HTTPS requests for `LOCK_ACCOUNT`, `REVOKE_SESSION`, `DISABLE_FEATURE`, and separately approved parent-linked `UNLOCK_ACCOUNT`/`ENABLE_FEATURE`. Its unit tests use `httpx.MockTransport` to verify the actual method, URL, headers, JSON body and server state readback. No live application API was called.

The user supplied the actual backend source [Project-Leafy/api-server](https://github.com/Project-Leafy/api-server). Its baseline `6dab427f25f2a0192d085da9347ebcaf73dc067b` has no remediation admin endpoints; the companion `remediation-admin-api` patch adds the real secured routes and JWT/feature enforcement. The [Leafy contract example](../../deploy/aiops-pc/remediation-app-api.leafy.example.yml) maps to those new routes and DTOs. It requires deploying the companion code and reviewed schema migration; it does not claim the current deployed image already provides them. The main config remains deny-all. `api-docs.json` in this repository is a Kakao HTML login page and is not used as an API specification.

## Operator configuration

Set `REMEDIATION_APP_API_CONFIG_PATH` to an operator-owned YAML or JSON file. An empty path blocks execution. The root schema is `version: 1` and `targets`, keyed by the exact observation target. Every target requires:

- `identity`: exact `site`, `service`, `source`, `runtime`, `target` values.
- `api_contract_verified: true` and `contract_source`: evidence that the administrator verified the server contract, permissions, conditional writes, idempotency and readback.
- `base_url`: fixed HTTPS origin with no credentials, query, fragment or path. Redirects are disabled. Loopback, metadata/link-local, multicast and ambiguous numeric hosts are rejected. Internal HTTPS addresses may be used only in this operator-owned configuration.
- Exactly one `token_env` or absolute `token_file` reference. Credential values are read at request time and never stored in the plan or result. `token_header` is `Authorization` or `X-API-Key`; `token_scheme` is `Bearer`, `Token` or `raw`.
- `timeout_seconds`: integer from 1 to 30, default 10.
- `account_allowlist`, `allowed_account_roles` for account operations. Administrator, owner, system and service roles are prohibited. `feature_allowlist` is required for feature changes.
- `actions`: explicit contracts for the requested action names. Every action has `method`, `path`, `body`, and `readback`. No action path or request parameter can supply another origin, shell command, arbitrary header or secret.

Example shape, using **synthetic test endpoints only**:

```yaml
version: 1
targets:
  fixture-backend:
    identity:
      site: fixture-gc
      service: backend
      source: fixture-docker
      runtime: container
      target: fixture-backend
    api_contract_verified: true # Synthetic fixture; not evidence about the Leafy backend.
    contract_source: synthetic-test-contract-only
    base_url: https://admin.fixture.invalid
    token_env: FIXTURE_APP_API_TOKEN
    token_header: Authorization
    token_scheme: Bearer
    timeout_seconds: 10
    account_allowlist: [acct-1]
    allowed_account_roles: [USER]
    feature_allowlist: [feature-1]
    actions:
      LOCK_ACCOUNT:
        method: POST
        path: /fixture/accounts/{resource_id}/lock
        body:
          target: '{target}'
          account_id: '{resource_id}'
          duration_seconds: '{duration_seconds}'
          reason: '{reason}'
        readback:
          path: /fixture/accounts/{resource_id}
          target_field: target
          resource_field: resource.id
          role_field: resource.role
          action_field: last_operation.action
          version_field: version
          state_fields: {locked: true}
          expires_at_field: lock_expires_at
          idempotency_field: last_operation.idempotency_key
```

`api_contract_verified` is an explicit administrator attestation, not automatic API discovery. The adapter cannot prove that a server implements the contract merely because that boolean is present.

## Request and readback rules

Templates allow only `{resource_id}`, `{target}`, `{action_type}`, `{duration_seconds}`, `{reason}`, and `{expires_at}`. Whole-placeholder JSON values preserve integer/boolean types. Paths may use only resource, target and action identifiers. Resource IDs are allowlisted single path segments. Query strings, percent encodings, traversal, template attribute/index access and format conversions are rejected.

`LOCK_ACCOUNT` parameters are `account_id`, mandatory integer `duration_seconds` from 1 to 86400, and optional `reason`. `REVOKE_SESSION` accepts `account_id` and optional `reason`. `DISABLE_FEATURE` accepts `feature_id` and optional `reason`. These parameters cannot add arbitrary body fields. Each contract's readback `state_fields` names the server fields and exact expected scalar values: for example a lock flag, zero active sessions, or a disabled feature flag.

Before approval, a GET confirms the exact server-returned target, account/feature ID, resource version, role and current state. An already satisfied desired state is not mutated again. The persisted plan contains the identity, action, normalized parameters, configuration digest and sanitized resource snapshot. A changed configuration, identity, account role, state, version or action requires a new plan and approval.

Execution requires an incident-bound durable action hash, the `app_api` executor marker, persisted plan evidence, an unexpired manual approval and the Controller's `EXECUTING` claim. Approval ordering and expiry are checked again after preflight, immediately before the mutation. Writes carry `If-Match` with the approved version and a deterministic `Idempotency-Key` derived from remediation ID, target and action. The API contract must enforce these headers; an API that ignores them is unsuitable for this executor.

HTTP 200 alone is insufficient. A fresh GET must return the same target and resource ID, the exact requested action, changed resource version and every expected state value. When configured, its operation key must match the idempotency key. Account locks must expose a future server-enforced expiration no later than the requested duration plus five seconds. The adapter records that verified expiry; it does not run a timer that silently makes an account lock permanent.

After a mutation request, a timeout, redirect, non-success response, malformed readback or unconfirmed effect yields `UNKNOWN`. The adapter sends exactly one mutation request and does not retry. The Controller preserves `UNKNOWN` for manual review. Read-only preflight failures block execution. Unlocking accounts and reenabling features require separately reviewed API contracts and approvals; automatic restore is not implemented by this adapter.

## Companion Leafy contract

All routes are under `/api/admin/remediation`, require a current ADMIN access JWT, and return raw JSON DTOs matching the example's readback paths.

| Operation | Method/path | Request resource field | Verified state |
|---|---|---|---|
| Account preflight | GET `/accounts/{id}` | Numeric existing User ID in path | target/resource.id/resource.role/version |
| LOCK_ACCOUNT | POST `/accounts/{id}/lock` | account_id, duration_seconds, target | locked=true and bounded lock_expires_at |
| REVOKE_SESSION | POST `/accounts/{id}/revoke-sessions` | account_id, target | sessions_revoked=true; old JWT authorization epoch rejected |
| Feature preflight | GET `/features/{id}` | Fixed feature ID in path | target/resource.id/version |
| DISABLE_FEATURE | POST `/features/{id}/disable` | feature_id, target | enabled=false and actual controller handler blocked |

Mutation requests additionally require `If-Match` and `Idempotency-Key`. State, version and durable operation receipt commit together in the companion backend. `last_operation.action` and `last_operation.idempotency_key` bind post-readback to the submitted action. ADMIN accounts are excluded from target operations. New token issuance after revocation resets the session status and uses the new epoch, allowing later incidents to revoke newly issued sessions again.

The backend also supplies explicit ADMIN `/accounts/{id}/unlock` and `/features/{id}/enable` recovery routes. The Controller does not automatically invoke them. Feature IDs match actual Leafy handlers: diagnosis, plant-identification and recommendations. Lock expiry is enforced by server-side authentication checks; it does not depend on the Controller staying online.

Source-backed route/DTO checks use the Python adapter tests and the companion Java security/service/persistence tests. Live JWT issuance, schema migration, application rollout and production mutations are separate acceptance steps and have not been performed here.


Application restoration is initiated through the Controller `/recovery/request` API and a new
Slack recovery approval. Direct RCA recommendations or plain `/action` restoration calls are
rejected. The stored verified parent determines the resource; the adapter pins its current
version and requires `recovery_of` before any mutation. See [integration report](REMEDIATION_INTEGRATION.md).
