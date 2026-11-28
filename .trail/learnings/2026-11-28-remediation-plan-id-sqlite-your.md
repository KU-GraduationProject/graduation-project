---
title: "Remediation 판단 이벤트는 레코드 생성 뒤에 남기고, 이벤트의 plan_id는 SQLite 원래 값을 쓴다"
author: Your
date: 2026-11-28
branch: feat/81-remediation-event-keys
id: l-b2146668
scope: repo
status: active
src: agent
touches:
  - aiops/remediation/main.py
  - aiops/remediation/recovery.py
---

## Decided
- policy_decision 이벤트는 조치 레코드가 만들어진 뒤에 push해서 remediation_id를 같은 이벤트에 싣는다. 보완 이벤트를 따로 내는 방식은 Gold가 두 이벤트를 조인해야 해서 고르지 않았다(사용자 결정, #81).
- 레코드 전에 끝나는 경로(BLOCKED·NO_ACTION·NOTIFY, 422 파라미터 오류, 409 IncidentConflict, 503 저장소 불가)도 remediation_id 없이 policy_decision을 남긴다. 판단 기록이 빠지면 안 된다.
- 레코드 이벤트의 plan_id는 SQLite 컬럼 값 그대로다. 루트·단일 단계 레코드는 null이고 연결 레코드만 루트 remediation_id를 가진다. /action 응답의 plan_id(plan_id or remediation_id)와 다르다. 데이터 플랫폼은 coalesce(plan_id, remediation_id)로 묶는다.

## Watch out
- _propose_action에 레코드 생성 전 새 종료 경로를 추가하면 그 앞에서 _push_policy_decision을 불러야 한다.
- policy_decision의 identity는 store.incident_key()처럼 검증하지 않고 라벨 값을 그대로(없으면 None) 싣는다. 검증 실패(422) 경로에서도 이벤트를 남기기 위해서다.

In the code: aiops/remediation/main.py _propose_action·_push_policy_decision, aiops/remediation/recovery.py timings_event, 테스트 aiops/remediation/tests/test_event_keys.py
