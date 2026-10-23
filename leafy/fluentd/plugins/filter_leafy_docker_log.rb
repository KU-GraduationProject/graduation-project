# Docker fluentd log driver 레코드 -> Loki 앱 로그 레코드 (fluent.conf @DOCKER_APP)
#
# Fluentd는 @type 이름으로 filter_<이름>.rb 파일을 찾으므로 필터마다 파일을 나눈다.
# PostgreSQL 쪽은 filter_leafy_postgres_log.rb.
#
# 내장 filter_parser를 쓰지 않는 이유 (fluentd 1.16.3 소스로 확인):
#   - json 파서는 기본으로 "time" 키를 꺼내 float으로 해석한다. Nginx JSON의 "time":"..." 같은 문자열이면
#     파싱 오류가 되어 emit_invalid_record_to_error false일 때 레코드가 조용히 버려진다.
#   - 123, [..] 처럼 객체가 아닌 JSON은 reserve_data의 Hash#merge에서 TypeError가 나 같은 방식으로 버려진다.
#   - reserve_data + emit_invalid_record_to_error 조합은 실패 레코드를 정상 경로와 @ERROR에 이중으로 보낸다.
#
# 계약 (filter_leafy_postgres_log.rb도 같다)
#   - Loki label 값은 _lbl_* 키에 넣는다. out_loki <label>이 읽고 line에서 지운다.
#     앱 JSON에 service/source 같은 키가 있어도 본문과 label이 섞이지 않게 하기 위해서다.
#   - 본문(line)은 항상 JSON 객체다. 해석하지 못한 로그도 버리지 않고 원문을 보존한다.

require "json"
require "fluent/plugin/filter"
require_relative "leafy_log_size"

module Fluent::Plugin
  class LeafyDockerLogFilter < Filter
    Fluent::Plugin.register_filter("leafy_docker_log", self)

    desc "Loki line 최대 bytes. 넘으면 큰 필드를 줄이고 log_truncated를 남긴다 (Loki max_line_size보다 작게)"
    config_param :max_line_bytes, :size, default: 240 * 1024

    # concat이 정상 재조립하면 지우는 키. 남아 있으면 마지막 조각 없이 timeout/shutdown으로 방출된 레코드다.
    PARTIAL_MESSAGE_KEY = "partial_message".freeze
    MAX_ERROR_CHARS = 200

    # Identity (NETWORK_EVENT_SCHEMA.md §4, 기존 fluent.conf 규칙 유지):
    #   container      [LEGACY]    Fluentd tag 그대로. Pipeline 프롬프트가 아직 표시용으로 읽는다. 신규 조회에 쓰지 말 것.
    #   source         stdout | stderr
    #   service        [canonical] com.docker.compose.service 라벨 (logging 옵션 labels로 전달돼야 한다)
    #   container_name [canonical] "/leafy-backend" -> "leafy-backend". 없으면 nil -> Loki label이 생기지 않는다
    #   runtime        container_id가 있으면 container
    #   log_format     json | text | json_invalid  ('{'로 시작했는데 파싱 실패 = 잘린/깨진 JSON)
    def filter(tag, _time, record)
      raw = utf8(record["log"]).chomp
      docker = record.reject { |k, _| k == "log" }
      body, format, error = parse_body(raw)

      body["log_parse_error"] = error if error
      body["log_partial_incomplete"] = true if record.key?(PARTIAL_MESSAGE_KEY)
      # 앱이 같은 이름의 키를 쓰면 덮어쓰지 않는다
      body[body.key?("docker") ? "_docker" : "docker"] = docker
      body = LeafyLogSize.fit(body, @max_line_bytes)

      container_name = record["container_name"]
      body.merge(
        "_lbl_container" => tag,
        "_lbl_source" => record["source"] || "stdout",
        "_lbl_service" => record["com.docker.compose.service"] || "unknown",
        "_lbl_container_name" => container_name && container_name.sub(%r{\A/}, ""),
        "_lbl_runtime" => record["container_id"] ? "container" : "unknown",
        "_lbl_log_format" => format,
      )
    end

    private

    # JSON 객체 로그는 필드를 그대로(키 순서 유지) 본문으로 쓰고, 그 외는 원문을 message에 담는다.
    # 시각은 바꾸지 않는다 (Docker driver 시각 유지). 앱의 timestamp 필드는 문자열 그대로 남아 offset이 보존된다.
    def parse_body(raw)
      return [{ "message" => raw }, "text", nil] unless raw.lstrip.start_with?("{")

      parsed = JSON.parse(raw)
      return [parsed, "json", nil] if parsed.is_a?(Hash)

      [{ "message" => raw }, "json_invalid", "not a JSON object"]
    rescue JSON::ParserError => e
      [{ "message" => raw }, "json_invalid", e.message[0, MAX_ERROR_CHARS]]
    end

    # 잘못된 UTF-8이 섞이면 out_loki의 Yajl 직렬화가 실패해 chunk 전체가 재시도에 묶인다.
    def utf8(value)
      value.to_s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD")
    end
  end
end
