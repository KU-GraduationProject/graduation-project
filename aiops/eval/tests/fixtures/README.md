# 테스트용 가짜 픽스처

하네스(`aiops/eval/harness.py`) 흐름 검증 전용이다. **실측이 아니며 지표 보고에 쓰지 않는다.**

- 형식은 `scenarios/v2/fixtures.build_fixture()` 와 같다(`scenario_id`·`variant_id`·`seed`·`alert`·`observations`).
  정답은 넣지 않고 `scenario_id` 로 레지스트리에서 조회한다.
- `fake-unlisted-variant.json` 은 공개 튜닝 변형이 아닌 변형 id 를 가진 픽스처로, 평가 분할이
  기본 실행에서 빠지는지 확인하는 용도다(실제 평가용 변형과 무관한 임의 이름).
- `fake-minio-down.json` 은 `observations` 의 별칭 키(`loki`·`prometheus`)와 룰 값 조회 실패 표시를 확인한다.
