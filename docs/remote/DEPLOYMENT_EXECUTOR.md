# Deployment executor: RECREATE and ROLLBACK

Requirements come from the [Remediation proposal](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85), including sections 7.4–7.6. The implementation is [deployment.py](../../aiops/remediation/executor/deployment.py). Its Docker SDK call contract and failure boundaries are covered by [test_deployment_executor.py](../../aiops/remediation/tests/test_deployment_executor.py).

The adapter makes real Docker SDK calls for two operations:

- `RECREATE` deploys the current immutable image with the operator's desired command, entrypoint and deployment configuration. It can repair the F3-a command override without choosing another application version.
- `ROLLBACK` deploys one explicitly configured known-good version and immutable image. The request may supply `action_parameters: {version: "configured-version"}`; omitting the version selects that configured version. No other rollback version is accepted. `RECREATE` accepts an empty parameter object only.

Targets are exactly `leafy-backend` and `leafy-frontend`, with the matching `backend` or `frontend` service identity. Their image repositories are the current Compose repositories, `gicks/ai-ops-leafy-backend` and `gicks/ai-ops-leafy-frontend`. DB, MinIO, observer and management services cannot be deployment targets. Every operation requires a fresh manual approval.

## Execution host and private configuration

Set `REMEDIATION_DEPLOYMENT_CONFIG_PATH` to the mounted operator-owned configuration. Base Compose supplies an empty `version: 1, targets: {}` file, so no deployment is allowed by default. `REMEDIATION_DEPLOYMENT_CONFIG_LOCAL_PATH` selects the private host-side file for that mount. The [reference configuration](../../deploy/aiops-pc/remediation-deployment.example.yml) also loads as deny-all; its complete backend/frontend profiles are commented out and contain invalid placeholders.

Deployment execution must run beside the intended Docker daemon. The adapter uses only `unix:///var/run/docker.sock`. It does not use `DOCKER_HOST`, Docker TCP/TLS, an arbitrary URL or the existing remote primitive-command Agent. Images must already exist on that daemon and have a tag or repository digest identifying the configured Leafy repository; the adapter never pulls or builds images.

The extended executor mode selects this adapter, but selection alone supplies neither a Docker socket nor valid deployment targets. A deployment operator must separately provide the local socket and readonly mounts for the private environment file, backup manifest and backup artifact. DB/app API adapters do not need a Docker socket. The socket exposes Docker mutation capability; marking its filesystem mount readonly does not make the Docker API readonly.

Private environment and backup files stay outside Git. Absolute paths in `environment_file`, `backup_evidence_file` and the manifest's `artifact_path` must resolve **inside the executor runtime**. Mount the private directory at the same absolute path, or prepare a reviewed manifest using the mounted runtime path. Bind-mount `source` paths inside a deployment spec refer to the **Docker daemon host**, which may differ from the executor container's filesystem. No socket or private-file mount is activated automatically by the example file.

## Operator deployment contract

The root configuration is `version: 1` and `targets`, keyed by the exact container name. Each target specifies all five observation identity fields, the current full 64-character container ID, the current `sha256:<64 hex>` image ID, the fixed repository, required labels and allowed `RECREATE`/`ROLLBACK` actions. Required labels include `io.leafy.remediation: workload` and the actual Compose project and service labels.

`desired` is a complete `DesiredSpec`. `desired.image_id` must equal `current_image_id`; `RECREATE` cannot change versions. `rollback` contains a `version` and a second complete `spec` whose image ID is the approved known-good image. The example uses YAML anchors to repeat the reviewed deployment specification while changing that image ID. The version label does not replace the image digest.

The deployment specification records:

- `command` and `entrypoint`: fixed lists, or explicit `null` to inherit the pinned image's normal values. Copy the intended original settings, not the F3-a injected failure command. Request parameters cannot override them.
- `environment_file` and `environment_sha256`: an absolute private JSON file reference and the SHA-256 of its exact bytes. The JSON object contains string environment names and string values. Changing the file or hash revokes the plan. The plan and execution result contain the reference/hash, never the plaintext values.
- `healthcheck`: an explicit direct `CMD` probe, `interval_ns`, `timeout_ns`, `retries` and `start_period_ns`. Shell healthcheck strings and `CMD-SHELL` are rejected. Verify the probe executable and readiness endpoint against the actual image; the reference health path is illustrative, not a verified Leafy endpoint.
- `networks`: actual network names and full immutable network IDs, explicit IPv4 addresses and required aliases. Enumerate every current attachment, including management networks. Existing attachment names/IDs must match the reviewed topology. The adapter releases old endpoints and gives the replacement the desired addresses; it does not discover or guess a topology.
- `ports`: explicit container `port/protocol` entries with host IP/port bindings. An unspecified host IP such as `0.0.0.0` is rejected. `mounts` declares each bind or named-volume source, destination and readonly flag. Image-declared anonymous volumes without an explicit mount are rejected. Host control mounts are prohibited; volumes are never removed or pruned.
- `restart_policy`, logging driver/options, memory/swap bytes, CPU quota/period, user, working directory and root-filesystem readonly state. These are verified after creation. Configure the actual Fluentd profile when preserving the current telemetry path.

For the current backend Compose profile, memory and swap are both 512 MiB, there is no published host port, and the application joins both Leafy and management networks. The current frontend publishes port 80, uses a readonly `stub_status.conf` bind mount and joins the Leafy network. All network IDs, addresses, host paths, image digests and readiness commands still require actual host verification. `stop_timeout_seconds` defaults to 10 and `health_timeout_seconds` to 90.

## Backend credentials and schema guard

The current backend dev image can default to `create-drop`. Therefore backend execution requires an explicit private environment file with nonempty `SPRING_DATASOURCE_URL`, `DB_USERNAME_DEV`, `DB_PASSWORD_DEV`, `JWT_SECRET_KEY_DEV`, `STORAGE_ACCESS_KEY` and `STORAGE_SECRET_KEY`. It also requires an explicit `SPRING_JPA_HIBERNATE_DDL_AUTO` of `none`, `validate` or `update`. `create`, `create-drop` and `drop` are rejected. Preserve other required application settings, including the intended Spring profile, in that private file as needed by the reviewed image.

Backend `ROLLBACK` additionally requires `rollback.schema_compatible: true`, `backup_database_id` and `backup_evidence_file`. `schema_compatible` is an operator assertion following compatibility review. The adapter does not inspect Hibernate migrations or prove schema compatibility automatically. It does not restore a database or execute schema DDL. The approved application image may itself perform its configured schema behavior when started; review that effect before approving a version rollback.

The backup manifest must have this shape; values below are illustrative placeholders, not a backup or an attestation:

```json
{
  "verified": true,
  "format": "postgres-custom",
  "restore_list_verified": true,
  "database_id": "REPLACE_WITH_VERIFIED_DATABASE_ID",
  "artifact_path": "/run/remediation-backups/REPLACE_WITH_ACTUAL_BACKUP.dump",
  "sha256": "REPLACE_WITH_FULL_64_HEX_BACKUP_HASH",
  "verified_at": "REPLACE_WITH_ACTUAL_TIMEZONE_AWARE_VERIFICATION_TIME"
}
```

The configured database ID must match the manifest. The artifact must reside outside this repository, begin with the PostgreSQL custom-format `PGDMP` header and match its SHA-256. Verification must be no more than 24 hours old and cannot be in the future. The adapter checks the file header, content hash, scope and manifest freshness. `restore_list_verified` records a previously completed `pg_restore --list` verification; this adapter does not run that verifier or generate the backup. A boolean in a hand-written manifest is not proof of a restore test. Frontend rollback does not assert backend DB compatibility or require this backend backup contract.

## Durable execution and retained containers

Before approval, the Controller persists the complete operator-derived plan, its digest, the selected image and sanitized current container/configuration/network evidence. The Slack approval summary identifies the selected image and previous container. If a known-good version is selected by default, it is still the version configured in the persisted rollback plan.

Execution requires the Controller's incident-bound action hash, the `deployment` executor marker, the `EXECUTING` claim, matching persisted plan evidence, and an unexpired manual approval with the correct timestamp ordering. The adapter rereads the operator configuration and current target. Changes to either require a new plan and approval. Approval is checked after preflight and immediately before each Docker write, including after a slow network lookup. One target cannot have overlapping deployments in the same adapter instance.

The adapter then disables the old container's restart policy, stops it and verifies that it is stopped. It renames the old container to an audit name containing the remediation ID and disconnects its recorded endpoints. It creates the replacement from the approved local immutable image, attaches the exact reviewed networks, starts it and polls the configured health state. All mutating calls use immutable object IDs. No old container, image or volume is deleted.

Success requires a fresh inspect confirming the new image, record audit label, command/entrypoint, effective environment in memory, healthcheck definition, networks/IPs/aliases, ports, mounts, resources, logging/restart configuration and a running `healthy` state. Results contain the old and new IDs and `requires_rebinding: true`. The previous approval is never transferred to the new container. Update observation/execution bindings and the next deployment's current ID/image through a separately reviewed configuration before another action.

Any timeout, unconfirmed stop, partial topology change, failed creation, mismatched configuration or unconfirmed health **after mutation begins** becomes `UNKNOWN`. A lost create response may leave the new ID unknown to the Controller even if Docker created it. The retained old ID, deterministic audit name and the new container's `io.leafy.remediation.record` label support manual inspection. The adapter does not resend the operation, delete a partial replacement or silently restart the old container. `UNKNOWN` also keeps the target's in-process lease; process startup reconciliation and the Controller's durable incident record remain the cross-restart protection.

For manual reconciliation, first compare the Controller record with the actual immutable old/new IDs and audit labels. Determine which container is running and which endpoints and ports it owns. Choose a reviewed recovery plan; restoring the retained container requires its recorded original networks, aliases, addresses and restart policy. Do not reapprove the old request or infer success from a container name alone. Clean up retained artifacts only after the service state and recovery evidence have been reviewed.

## Verification boundary

The deployment suite contains 18 isolated tests using injected FakeDocker objects. It checks real SDK method arguments and the real SDK container serializer, target/config/secret changes, backup scoping, approval chronology and expiry, overlapping incidents, retained evidence, response loss and failed health verification. It does not start Docker, change a real deployment or demonstrate live backend/schema compatibility. Real image readiness probes, Docker-host topology and successful service recovery still require the operator's environment acceptance test.

SDK references: [low-level container creation and networking](https://docker-py.readthedocs.io/en/stable/api.html), [network connection methods](https://docker-py.readthedocs.io/en/stable/networks.html).


PC1→PC2 통합은 [현재 통합 보고](REMEDIATION_INTEGRATION.md)를 따른다. 네이티브 SDK는
계속 PC2 로컬 Unix socket만 사용하며 PC1은 인증된 Agent 계획/배포 API로 전달한다.
