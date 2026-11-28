---
title: "발표 흐름은 주입 정리 시점과 서비스 복구 확인을 분리한다"
author: Your
date: 2026-11-28
branch: feat/87-presentation-tui
cost: { minutes: 14, tokens: 53326 }
id: l-deab0488
scope: repo
status: active
src: agent
touches:
  - aiops/remediation/presentation.py
  - deploy/presentation.compose.yml
  - docs/demo/PRESENTATION_TUI.md
---

## Decided
- 발표 TUI는 v2의 기존 inject/cleanup/watchdog을 감싼 worker로 승인 동안 장애를 유지하고, 기존 service_verification의 service_recovered_at이 있을 때만 COMPLETED를 표시한다. 명령 성공은 서비스 복구가 아니므로 TTR 종료점으로 쓰지 않는다.
- TTD 시작은 실제 inject acknowledgement 이벤트, 탐지 끝은 기존 캡처 received_at이다. 주입 훅이 없는 시나리오는 시간을 추정하지 않고 평균 표본에서 제외한다. 대상 5필드·fingerprint·startsAt·시간창이 모두 맞는 사건만 연결한다.
## Tried and ruled out
- 레거시 런처의 /results 폴링 재사용: 현재 Pipeline에는 그 엔드포인트가 없어 연결 불가. 기존 CONTEXT_CAPTURE_DIR와 Loki aiops-llm, 서명된 remediation 읽기 모델을 사용한다.
- v2 main()을 detached 시나리오에도 그대로 호출: 일부는 inject 직후 finally에서 cleanup하므로 Slack 승인 전에 장애가 사라진다. 명시적인 생명주기 어댑터만 inject/cleanup을 분리한다.
## Watch out
- LLM 담당 코드·prompt·schema와 scenarios/run.py는 변경하지 않는다. 증거 ID 표시는 기존 v2 formatter를 별도 프로세스에서 읽기 전용 재사용한다.
- Incoming Webhook은 message ts를 주지 않는다. 실제 메시지 permalink에는 SLACK_BOT_TOKEN과 chat.postMessage/getPermalink 경로가 필요하며 승인 처리 자체는 기존 HITL이다.
In the code:
- scenarios/presentation/{worker,state,client,evidence}.py
- aiops/remediation/presentation.py, main.py, actions/notify.py
- deploy/presentation.compose.yml, docs/demo/PRESENTATION_TUI.md
