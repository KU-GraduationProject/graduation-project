# Windows 호스트 PostgreSQL 17 jsonlog (팀원 PC Fluent Bit -> forward 24225) -> Loki 레코드 (fluent.conf @POSTGRES)
#
# Loki label 값은 _lbl_* 키에 넣는다 (filter_leafy_docker_log.rb와 같은 계약).

require "time"
require "fluent/plugin/filter"
require_relative "leafy_log_size"

module Fluent::Plugin
  class LeafyPostgresLogFilter < Filter
    Fluent::Plugin.register_filter("leafy_postgres_log", self)

    desc "Loki label service (canonical service)"
    config_param :service, :string
    desc "Loki label runtime (host: 컨테이너가 아닌 호스트 프로세스)"
    config_param :runtime, :string
    desc "Loki line 최대 bytes. 긴 statement 등은 줄이고 log_truncated를 남긴다 (Loki max_line_size보다 작게)"
    config_param :max_line_bytes, :size, default: 240 * 1024

    # jsonlog timestamp 형식: "2026-10-23 14:01:02.123 KST" (끝은 log_timezone의 약어)
    # 약어는 표준이 아니므로 아는 것만 offset으로 바꾼다. Asia/Seoul은 DST가 없어 KST=+09:00 고정이 안전하다.
    # 모르는 약어를 로컬 시각으로 추측하면 9시간 어긋난 시각이 조용히 저장되므로 대신 수신 시각을 쓰고 표시한다.
    ZONE_OFFSETS = { "UTC" => "+00:00", "GMT" => "+00:00", "KST" => "+09:00" }.freeze
    PG_TIMESTAMP = /\A(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) (\S+)\z/
    NUMERIC_ZONE = /\A([+-])(\d{2}):?(\d{2})?\z/ # log_timezone이 'Etc/GMT-9'이면 약어가 "+09"

    # PostgreSQL 필드는 그대로 둔다 (timestamp 원문 포함). Loki entry 시각만 timestamp로 맞춘다.
    # 수신 측(Fluent Bit)은 읽은 시각을 붙이므로, 재연결 후 밀린 로그도 원래 시각에 놓이게 하려는 것이다.
    def filter_with_time(_tag, time, record)
      out = record.dup
      has_timestamp = record.key?("timestamp")
      log_time = has_timestamp ? parse_pg_time(record["timestamp"]) : nil
      out["log_time_parse_error"] = "unsupported timestamp: #{record["timestamp"]}"[0, 200] if has_timestamp && log_time.nil?
      out = LeafyLogSize.fit(out, @max_line_bytes)

      out["_lbl_service"] = @service
      out["_lbl_runtime"] = @runtime
      # Fluent Bit이 JSON 파싱에 실패하면 {"log": 원문}으로 온다
      out["_lbl_log_format"] = has_timestamp ? "json" : "text"
      [log_time || time, out]
    end

    private

    def parse_pg_time(value)
      m = PG_TIMESTAMP.match(value.to_s) or return nil
      offset = ZONE_OFFSETS[m[3]] || numeric_offset(m[3]) or return nil
      Fluent::EventTime.from_time(Time.iso8601("#{m[1]}T#{m[2]}#{offset}"))
    rescue ArgumentError
      nil
    end

    def numeric_offset(zone)
      m = NUMERIC_ZONE.match(zone) or return nil
      "#{m[1]}#{m[2]}:#{m[3] || "00"}"
    end
  end
end
