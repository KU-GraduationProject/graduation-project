FROM fluent/fluentd:v1.16-debian-1

USER root
# 버전 고정: 재빌드마다 플러그인이 바뀌어 로그 형식(line/label)이 달라지는 것을 막는다.
#   grafana-loki : Loki 출력
#   concat       : Docker fluentd driver가 16KB 단위로 쪼갠 partial 로그 재조립 (use_partial_metadata)
RUN gem install fluent-plugin-grafana-loki -v 1.3.0 --no-document \
 && gem install fluent-plugin-concat -v 2.6.2 --no-document
# 앱/PostgreSQL 로그 -> Loki 레코드 변환 (leafy_docker_log, leafy_postgres_log). 이미지 entrypoint가 /fluentd/plugins를 로드한다.
COPY plugins/ /fluentd/plugins/
USER fluent
