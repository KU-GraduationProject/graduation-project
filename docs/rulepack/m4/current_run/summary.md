# M4 Baseline 분석 실행 결과

상태: **BLOCKED** / NORMAL_UNCONFIRMED / data_kind=none

M4 판정: **분석 도구 및 오프라인 검증 완료 / 실측 Baseline 수립 대기**이다.

확정 Baseline 사용 가능 시계열: 0개이다. 실제 경보 발화는 미검증이다.

| Query / source / entity | 단위 | 표본 | 정상 P95 | 정상 P99 | for 충족 구간 | Baseline 제외 사유 |
|---|---|---:|---:|---:|---:|---|

실측 입력이 없어 평균·분위수·임계값 초과 횟수·후보 임계값을 산출하지 않은 상태이다.

진단 통계는 정상 판정이 아니다. 집계는 source/시계열별이며 수집 누락을 0으로 채우지 않는다.
정상 미확인/합성 입력의 분위수는 JSON과 이 표에서 산출 결과로 제공하지 않는다.
for 충족 구간은 표본 기반 후보이다. 실제 Ruler 상태·Alertmanager 알림 횟수/FPR/재현율을 뜻하지 않는다.
