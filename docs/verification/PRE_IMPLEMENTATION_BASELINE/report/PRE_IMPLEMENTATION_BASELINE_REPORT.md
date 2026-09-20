# Pre-Implementation Baseline Report

## Environment
- OS / Docker environment: Docker Desktop (WSL2 backend), Server `linux/amd64 28.5.1`, Kernel `6.6.87.2-microsoft-standard-WSL2`, host OS Windows 11
- Checked at: 2026-09-20 12:38 UTC (2026-09-20 21:38 KST)
- Git branch: `main`
- Git commit: `624b54b378140f32f366f76c8d562e231c614a51` (2026-09-19 15:43:23 +0900)
- Note: working tree has pre-existing uncommitted changes unrelated to this check (e.g. `current_info_files/*.md`, `legacy_info_files/*` show as deleted in `git status`, `scenarios/logs/*` has new/modified files). These were **not** touched or restored as part of this baseline check.

## Summary
- **Final Status: PARTIAL MATCH**

## Docker Compose
`docker compose config --services` was used to enumerate services actually defined by `docker-compose.yml` (no file was modified).

| Check | Expected | Actual | Status | Evidence |
|---|---|---|---|---|
| prometheus defined | present | present | PASS | `docker compose config --services` output |
| fluentd defined | present | present | PASS | same |
| db defined | present | present | PASS | same |
| backend defined | present | present | PASS | same |
| loki defined | present | present | PASS | same |
| node-exporter defined | present | present | PASS | same |
| ollama defined | present | present | PASS | same |
| alertmanager defined | present | present | PASS | same |
| frontend defined | present | present | PASS | same |
| pipeline defined | present | present | PASS | same |
| remediation defined | present | present | PASS | same |
| postgres-exporter defined | present | present | PASS | same |
| cadvisor defined | present | present | PASS | same |
| grafana defined | present | present | PASS | same |
| nginx-exporter defined | present | present | PASS | same |

All 15 required services are defined in `docker-compose.yml`. (`version` obsolete warning noted separately below under Warnings, not treated as FAIL.)

## Leafy Network
Verified with `docker network inspect graduation-project_leafy-net`.

| Check | Expected | Actual | Status | Evidence |
|---|---|---|---|---|
| leafy-frontend running | Up | Up 16 min | PASS | `docker ps` |
| leafy-backend running | Up | Up 16 min | PASS | `docker ps` |
| leafy-db running | Up | Up 16 min | PASS | `docker ps` |
| leafy-db health | healthy | healthy (FailingStreak: 0) | PASS | `docker inspect leafy-db --format '{{json .State.Health}}'` |
| Network driver | bridge | bridge | PASS | `docker network inspect` → `"Driver": "bridge"` |
| Subnet | 172.18.0.0/16 | 172.18.0.0/16 | PASS | `docker network inspect` → `IPAM.Config` |
| Gateway | 172.18.0.1 | 172.18.0.1 | PASS | same |
| leafy-frontend attached | yes | yes (172.18.0.5/16) | PASS | `docker network inspect` `Containers` list |
| leafy-backend attached | yes | yes (172.18.0.4/16) | PASS | same |
| leafy-db attached | yes | yes (172.18.0.3/16) | PASS | same |
| fluentd attached | yes | yes (172.18.0.2/16) | PASS | same |

(Per instructions, the last octet of each IP was recorded as observed but is not treated as a fixed expected value — only presence/attachment is a pass criterion.)

## Application Traffic
Checked via nginx proxy config (`leafy/nginx/default.conf`), Fluentd/Loki tagging config (`leafy/fluentd/fluent.conf`, `docker-compose.yml` logging blocks), and live Loki query (`/loki/api/v1/query_range`) over the last hour, cross-referenced with `docker ps` uptimes.

| Flow | Expected | Actual | Status | Evidence |
|---|---|---|---|---|
| frontend → backend | actual application traffic exists | A real proxied request was observed and answered by the backend | PASS | `leafy/nginx/default.conf` routes `location /oauth2/` and `location /api/` to `proxy_pass http://backend:8080`. Loki `{container="frontend"}` log at `2026-09-20T12:24:24Z`: `GET /oauth2/authorization/kakao HTTP/1.1" 302` — this path only exists in Spring Security (backend), so the 302 response confirms the request reached and was processed by `leafy-backend`, not just a network-level ping. No `/api/` business-endpoint call was captured in the last hour, so this reflects OAuth-path traffic specifically; see Warnings for a suggestion on strengthening this evidence. |
| backend → db | actual DB traffic exists | Confirmed at process/schema level, not at live query level in the checked window | PASS (see caveat) | Loki `{container="backend"}` at container start (`~12:20:2x`): `HikariPool-1 - Added connection org.postgresql...`, `HikariPool-1 - Start completed`, plus multiple `Hibernate: create table ...` / `Hibernate: alter table ...` / `Hibernate: drop table ...` DDL statements — this is real application-level SQL executed by the backend against `leafy-db`, not an ICMP ping. In the checked 1-hour window, DB-side logs (`{container="leafy-db"}`) beyond this startup activity only show periodic `application_name=pg_isready` healthcheck connections (`client=[local]`, ~10s interval, session time 0.001–0.002s) — no additional live application query traffic was captured after startup. |

**MANUAL REQUIRED (recommended, to strengthen confidence beyond current automated evidence):**
- To directly confirm `frontend → backend` for a normal (non-OAuth) API call: log in to the app via `https://localhost/` and trigger a data-bearing feature (e.g. view/add a plant, view diagnosis history). Then check Loki: `{container="frontend"} |= "/api/"` should show the proxied request/response line, and `{container="backend"}` around the same timestamp should show corresponding Spring/Hibernate activity.
- To directly confirm `backend → db` with live (post-startup) query traffic: perform the same feature action above, then check `{container="leafy-db"}` in Loki for a `connection authorized` / query log entry with `application_name` other than `pg_isready` occurring within the same few seconds as the backend log entry.

## Application Log / Loki
Fluentd tag config (`docker-compose.yml` `logging.options.tag`) and Fluentd output plugin config (`leafy/fluentd/fluent.conf`, `<label> container $.container` / `source $.source`) were read directly from the repo. Loki was queried live for `label/container/values`, `label/source/values`, and `labels`.

Fluentd config note: the `<label>` block in `fluent.conf` emits exactly two labels to Loki — `container` and `source` (derived from `$.container` / `$.source` inside the fluentd record, not from a literal `service` field). Loki's own `/loki/api/v1/labels` confirms the full label set actually present is: `action_risk, alert, container, event, job, service_name, source, status, threat_level` — there is **no `service` label** in Loki; `service_name` is a separate label produced by a different pipeline (the `aiops`/remediation LLM output stream, tagged `job="aiops-llm"`), not by the Fluentd `fluent.conf` path described above.

| Service | Container | Expected Loki Identity | Actual | Status | Evidence |
|---|---|---|---|---|---|
| frontend | leafy-frontend | `container=frontend` (per `docker-compose.yml` tag `"frontend"`) | `container="frontend"` present with live access-log lines (last entry 12:24:24Z) | PASS | `docker-compose.yml:48` `tag: "frontend"`; Loki `label/container/values` includes `"frontend"`; query `{container="frontend"}` returns nginx access-log-style lines |
| backend | leafy-backend | `container=backend` (per `docker-compose.yml` tag `"backend"`) | `container="backend"` present with live application startup logs | PASS | `docker-compose.yml:87` `tag: "backend"`; Loki `label/container/values` includes `"backend"`; query `{container="backend"}` returns Spring Boot/Hibernate logs |
| db | leafy-db | `container=leafy-db` (per `docker-compose.yml` tag `"leafy-db"`) | `container="leafy-db"` present with live postgres logs | PASS | `docker-compose.yml:120` `tag: "leafy-db"`; Loki `label/container/values` includes `"leafy-db"`; query `{container="leafy-db"}` returns postgres connection/disconnection logs |

This matches the stated existing Loki application-log identity exactly: `leafy-frontend -> frontend`, `leafy-backend -> backend`, `leafy-db -> leafy-db` (the container name and the Fluentd `container` label value are intentionally different strings for frontend/backend, and intentionally the same string for db — confirmed as current, not assumed).

Separately (informational, not part of the canonical `frontend`/`backend`/`leafy-db` identity above): Loki also contains streams labeled `container="leafy-frontend"` and `container="leafy-backend"` with `job="aiops-llm"` — these come from the AIOps pipeline/remediation LLM analysis output (alert/root-cause JSON records), a different producer than the Fluentd app-log path, and use the raw container name rather than the Fluentd tag. This is pre-existing behavior, not a discrepancy introduced now — noted here only so it isn't mistaken for a second, conflicting app-log identity.

## Warnings
- `nginx-exporter`: container exists but is **Exited (0) 3 months ago** — not running. Per instructions, this is a WARNING only and does not fail the frontend/backend/db Network PoC baseline.
- `postgres-exporter`: container exists but is **Exited (2) 3 months ago** (non-zero exit code) — not running. WARNING only, same reasoning as above; worth noting the non-zero exit code in case it is unexpected downtime vs. an intentional stop.
- `docker-compose.yml`: `version` attribute is obsolete per Docker Compose (`the attribute 'version' is obsolete, it will be ignored`). Recorded as WARNING only, not a FAIL, per instructions.
- An unrelated container `community_was` (image `community_marketplace-was`, compose project `community_marketplace`) is present and currently in a `Restarting` crash loop on this host. It is **not part of** `graduation-project` (different compose project) and was excluded from this baseline entirely — flagged here only for situational awareness, no action taken.
- The working directory has pre-existing uncommitted git changes unrelated to this task (deletions under `current_info_files/`, `legacy_info_files/`, new files under `scenarios/logs/`, and an untracked `docs/` directory). These were left untouched, as instructed.
- `frontend → backend` evidence in this check window is limited to the OAuth redirect path; no `/api/` business-endpoint call was observed. See "MANUAL REQUIRED" above for how to capture stronger evidence.
- `backend → db` evidence for *live* (post-startup) query traffic was not captured in the checked window — only container-startup schema/connection-pool activity. See "MANUAL REQUIRED" above.

## Final Comparison
| Baseline item | Existing baseline expectation | Current observed state | Match? |
|---|---|---|---|
| Compose services (15) | all 15 defined | all 15 defined | Yes |
| leafy-frontend/backend/db running | Up | Up | Yes |
| leafy-db health | healthy | healthy | Yes |
| leafy-net driver/subnet/gateway | bridge / 172.18.0.0/16 / 172.18.0.1 | bridge / 172.18.0.0/16 / 172.18.0.1 | Yes |
| leafy-net members (frontend/backend/db/fluentd) | attached | attached | Yes |
| frontend → backend real traffic | must be actual app traffic, not ping | confirmed via OAuth proxy path + Loki log | Yes (partial: only OAuth path captured automatically) |
| backend → db real traffic | must be actual app traffic, not ping | confirmed via Hikari/Hibernate startup SQL; no live query captured in window | Yes (partial: startup-only evidence) |
| Fluentd tag → Loki `container` label mapping | frontend→frontend, backend→backend, db→leafy-db | frontend→frontend, backend→backend, db→leafy-db | Yes |
| Loki label schema | not to be guessed | confirmed via live query: `container`, `source`, plus separate `service_name`/`job` from aiops pipeline; no `service` label | Recorded as-is, consistent with Fluentd config read |
| nginx-exporter / postgres-exporter | non-blocking | both stopped | WARNING only, not a mismatch for this PoC |
| `version` obsolete warning | non-blocking | present | WARNING only, not a mismatch |

All mandatory items (compose services, core Leafy containers, `leafy-db` health, network topology, Fluentd→Loki identity mapping) match the expected baseline exactly. The two application-traffic checks are supported by real (non-ping) evidence but that evidence is narrower than full end-to-end feature coverage (OAuth-only for frontend→backend; startup-only for backend→db) — hence these are recorded as PASS-with-caveat rather than a fully saturated automated confirmation, and manual verification is recommended before treating traffic coverage as complete.

**자동 검증만으로 Baseline 전체를 확정할 수 없다. MANUAL REQUIRED 항목 확인 후 구현을 시작한다.**
