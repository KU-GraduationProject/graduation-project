---
title: "원격 Leafy 컨테이너 지표는 raw cAdvisor와 이름 붙이는 collector로 수집"
author: galgalrobot
date: 2026-11-26
branch: feat/61-remote-container-metrics
cost: { minutes: 1, tokens: 2252 }
id: l-ceec839c
scope: repo
status: active
src: agent
touches:
  - deploy/leafy-pc/telemetry/exporter.py
  - monitoring/prometheus/rules/alert.rules.yml
---

## Decided
- 분리 구성에서 Leafy 장비 컨테이너 지표는 cAdvisor를 Docker API 없이 raw cgroup 모드로 돌리고, collector(exporter)가 Docker 소켓 GET으로 이름·compose 서비스·site를 붙여 내보낸다. AIOps Prometheus는 collector만 수집한다.
- collector는 cAdvisor 샘플의 원래 시각을 그대로 내보낸다. 컨테이너 경보는 by (site, name)으로 집계해 출처 장비를 유지한다 (all-in-one은 site가 없어 결과가 같다).

## Tried and ruled out
- cAdvisor Docker 모드: Docker 29(containerd 이미지 저장소)에서 v0.49.1은 API 버전이 낮아 거부되고, v0.52.1은 모든 컨테이너에서 쓰기 레이어 조회에 실패해 id="/" 지표만 나온다 (맥 실측). 이름이 붙지 않는다.
- cAdvisor 시각을 버리고 수집 시각으로 내보내기: cAdvisor는 housekeeping 주기로만 값을 바꿔서 5초 수집이 같은 값을 연속으로 보게 되고 irate()가 0이 된다. CPU 부하 2코어인데 경보 식이 0을 냈다.

## Watch out
- Docker Desktop(맥·Windows)의 cAdvisor raw 출력에는 /docker/buildx 같은 서비스 cgroup이 섞인다. 64자리 컨테이너 id가 아니면 건너뛰어야 하고, 그렇지 않으면 exporter가 그 주기 전체를 버린다.
- Windows(WSL2)에서의 raw cgroup 경로는 아직 실측하지 않았다.

In the code:
- deploy/leafy-pc/telemetry/compose.remote.yml: gcr.io/cadvisor/cadvisor:v0.52.1, docker.sock 미마운트
- deploy/leafy-pc/telemetry/exporter.py: parse_metrics(Sample.ts 보존), resources()의 CID 형식 검사
- 확인: leafy_telemetry_collection_success{component="resources"} == 1
