# LLM 출력 ↔ Remediation 입력 계약

> 기준: `main` 5755eb5 (PR #44~#59 반영). Remediation·정책 엔진·실행기 코드는 읽기만 했다.
> 관련 이슈: #72

## 1. 흐름 요약

```
경보 → pipeline RCA(LLM) → LLMAnalysisResult
     → [승인 제안 켜짐] schemas/remediation_plan.build_proposal → POST /action (propose_manual_action | propose_rca_action)
     → [알림만]        POST /notify (notify_only)
Remediation: plans.normalized_analysis / validate_wire → policy_engine.decide_from_analysis
           → executor 선택(router) → 실행기별 대상·파라미터 검증 → 승인/자동 실행
```

실행 여부·위험도·승인은 정책 파일(`aiops/policy/remediation_policy.yml`)과 Remediation 코드가 정한다.
LLM은 무엇을(action_type)·어디에(대상)만 추천한다. `action_risk`는 LLM 출력에 없다.

## 2. Remediation이 받는 조치

`remediation_policy.yml` `actions`에 정의되고 `plans.FORWARD_ACTIONS`(제안 경로)에 있는 조치:

| action_type | 위험도 | 승인 | 실행기 | 대상(`action_targets`) | 파라미터(`action_parameters`) | LLM 허용 |
|---|---|---|---|---|---|---|
| NONE / NOTIFY | low | — | 없음(알림) | `[]` | 없음 | 예 |
| THROTTLE | medium | 자동 후보* | docker | 관측 target 1개 | 없음 | 예 |
| RESTART | high | 필수 | docker | 관측 target 1개 | 없음 | 예 |
| PAUSE | high | 필수 | docker | 관측 target 1개 | 없음 | 예 |
| ISOLATE | high | 필수 | docker | 관측 target 1개 | 없음 | 예 |
| KILL_SESSIONS | medium | 자동 후보* | postgres | 관측 target 1개(service=db) | `operation`은 정책 소유, `min_age_seconds`·`max_sessions`는 선택 | 예 |
| RECREATE | high | 필수 | deployment | 관측 target 1개(backend/frontend) | 없음 | 예 |
| ROLLBACK | high | 필수 | deployment | 관측 target 1개(backend/frontend) | `version`(선택) | 예 |
| LOCK_ACCOUNT | medium | 자동 후보* | app_api | 관측 target 1개(앱 서비스) | `account_id` 필수, `duration_seconds`는 정책 소유 | 예 |
| REVOKE_SESSION | high | 필수 | app_api | 관측 target 1개 | `account_id` 필수 | **아니오** (질문 Q1) |
| DISABLE_FEATURE | medium | 필수 | app_api | 관측 target 1개 | `feature_id` 필수 | **아니오** (질문 Q1) |
| UNLOCK_ACCOUNT / ENABLE_FEATURE | high | 필수 | app_api | — | — | 아니오 — 원 요청 검증이 필요한 복구 조치(`restoration_requires_verified_parent_request`) |
| SCALE | — | — | 없음(`unsupported`) | — | — | 아니오 |

\* 자동 실행은 `REMEDIATION_AUTO_EXECUTE_ENABLED=true`이고 정책 조건(confidence ≥ 0.8, threat_level medium/high)을 만족할 때만. 기본은 승인.

## 3. 대상 규칙 (Remediation 코드에서 확인)

- 모든 실행기는 `action_targets == [identity.target]`만 받는다(`executor/identity.py _configured`, `app_api._resolve`, `postgres.plan_record`, `deployment._rule`, `plans.validate_wire`). 대상은 LLM이 고르는 이름이 아니라 **경보의 관측 identity target**이다.
- 계정은 대상이 아니라 `action_parameters.account_id`다. 형식 `[A-Za-z0-9][A-Za-z0-9_-]{0,127}`(pipeline 제안), 운영자 `account_allowlist`(remediation_app_api.yml)에 있어야 실행된다.
- Docker 조치는 service가 backend/frontend/minio인 바인딩만(`executor/identity.py`), 배포 조치는 backend/frontend만(`deployment.REPOSITORIES`), KILL_SESSIONS는 service=db만.
- 정책이 소유한 실행 세부값(`LOCK_ACCOUNT.duration_seconds`, `KILL_SESSIONS.operation`)을 요청이 보내면 `policy_owned_action_parameter`로 거부한다.
- 운영 설정(remediation_targets / app_api / postgres / deployment yml)은 저장소에서 비어 있다. 실제 실행 가능 대상은 측정 PC 운영자 설정에 달려 있다.

## 4. LLM 출력 ↔ Remediation 입력 매핑 (이번 변경 후)

| LLM 출력 필드 | 변환 위치 | Remediation 입력 | 비고 |
|---|---|---|---|
| `action_type` | 그대로 | `analysis.action_type`, `plan.action_type` | 10개 허용(위 표 "LLM 허용") |
| `action_targets` = `[관측 target]` | `build_proposal` | `analysis.action_targets`, `plan.targets` | 관측 target과 다르면 pipeline에서 NOTIFY로 낮춤 |
| `action_targets` = `["account:<id>"]` (LOCK_ACCOUNT) | `build_proposal` | `action_parameters.account_id=<id>`, 대상은 관측 target | 계정 값은 증거에 있어야 함 |
| `target_evidence` (신규) | 전달 안 함 | — | pipeline 검증·기록용 |
| `target_validation`, `target_reason`, `proposed_action` (신규) | 전달 안 함(/notify는 전체 결과 전달) | — | 낮춘 이유를 사람에게 보여 주는 기록 |
| `threat_level`, `confidence`, `root_cause`, `evidence` | 그대로 | 같은 이름 | 의미 변경 없음 |
| `incident_class` | 그대로 | 기록(`RemediationRecord.incident_class`) | |
| `analysis_status` | 그대로 | invalid면 정책 엔진이 NOTIFY로 판단 | |

## 5. 맞지 않던 곳 (조사 시점)

| # | 내용 | 영향 | 이번 처리 |
|---|---|---|---|
| M1 | 대상 값(특히 계정)이 입력 증거에 있는지 검사하지 않음 | LLM이 만든 계정 이름이 그대로 제안될 수 있음 | pipeline 후처리로 검증, 없으면 NOTIFY |
| M2 | 출력 스키마의 대상 enum이 고정 4개(`leafy-backend/frontend/minio/db`) | 호스트 DB처럼 관측 target 이름이 다르면 맞는 값을 낼 수 없음 | 프롬프트별 후보(관측 target + 증거에 있는 계정)로 enum 생성 |
| M3 | 호스트 대상 안내가 KILL_SESSIONS 대상을 `leafy-db`로 고정 | 관측 target(예: 호스트 PostgreSQL 이름)과 달라 `action_targets_do_not_match_observation`으로 제안 거부 | 관측 target을 쓰도록 수정 |
| M4 | 대상별 근거 기록이 없음 | 사람이 대상의 근거를 확인할 수 없음 | `target_evidence` 추가 |
| M5 | 로그인 로그의 계정 필드(`login_id` 등)가 압축 로그 줄에 안 보일 수 있음 | 계정 근거를 증거로 인용할 수 없음 | 압축 줄에 계정 필드 포함 |
| M6 | 앱 기본 `LLM_PROVIDER=gemini`(#56), 평가 하네스는 Ollama 직접 호출 | 운영 판단 모델과 평가 모델이 다름 | 하네스 모델·옵션을 코드에 고정(llama3.1:8b, 0.3/4096/400). 앱 기본값도 #74에서 ollama로 변경 |
| M7 | Docker/배포/DB 대상 허용 규칙이 설정 파일이 아니라 Remediation 코드에 있고, pipeline 컨테이너에는 정책 파일이 마운트되지 않음 | pipeline이 "정책 설정을 읽어서" 서비스 허용 여부를 미리 알 수 없음 | 중복 정의하지 않음. 관측 target 일치만 검사하고 나머지는 Remediation에 맡김(제안 P1) |

## 6. Remediation 쪽 제안 (구현하지 않음)

- **P1.** 조치별 허용 runtime/service를 읽기 전용으로 노출(예: `GET /capabilities` 또는 정책 파일에 `allowed_services` 명시 + pipeline 읽기 전용 마운트). 그러면 pipeline이 실행 불가능한 조치를 미리 NOTIFY로 낮추고 이유를 보여 줄 수 있다.
- **P2.** `plans.ANALYSIS_KEYS`가 `incident_class`를 받지 않는다. 제안 경로에서도 기록하려면 키 추가가 필요하다(현재 `build_proposal`은 보내지 않음).
- **P3.** 제안 거부 사유(`/action` 422 detail)를 pipeline이 기록할 수 있게 응답 형식을 고정하면, 평가에서 "Remediation이 거부한 제안 비율"을 셀 수 있다.

## 7. 팀원 질문

- **Q1.** REVOKE_SESSION·DISABLE_FEATURE는 실행기가 준비돼 있지만 Notion 1차 범위(#30)에 따라 LLM 허용 목록에서 뺐다. 2차 조치를 LLM이 추천해도 되는가? DISABLE_FEATURE의 `feature_id`는 로그 증거로 근거를 대기 어렵다.
- **Q2.** LOCK_ACCOUNT의 계정 값은 로그 `login_id`/`user`류 필드에서만 인정했다. 앱이 로그에 남기는 계정 필드 이름이 그 밖에 있는가?
- **Q3.** KILL_SESSIONS의 `min_age_seconds`·`max_sessions`를 LLM이 정해야 하는가, 정책이 정해야 하는가? 이번 변경에서는 LLM이 보내지 않는다.
- **Q4.** (#74에서 해결) 운영 기본도 `LLM_PROVIDER=ollama`(llama3.1:8b)로 평가 모델과 맞췄다.
- **Q5.** 이상 조치(expected_action_ideal)를 정답으로 승격할지. 이번 하네스는 두 기준을 모두 보고하고 정답 기준은 바꾸지 않는다.
- **Q6.** 실행기가 관측 target 하나만 받으므로, S2-e처럼 이상 조치가 여러 단계(`ISOLATE+KILL_SESSIONS`)인 경우 LLM이 다단계를 내야 하는가, Remediation 계획(`propose_plan`)이 만드는가?
