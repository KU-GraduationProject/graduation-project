# Loki line 크기 제한 정책 (filter_leafy_docker_log.rb, filter_leafy_postgres_log.rb에서 사용)
#
# Loki는 limits_config.max_line_size(기본 256KB = 262144 bytes)를 넘는 줄을 400으로 거부하고,
# out_loki(fluent-plugin-grafana-loki 1.3.0)는 4xx를 재시도하지 않고 경고만 남긴 채 버린다 (실측: 300KB 줄 유실).
# Loki 한도를 키우는 대신, 보내기 전에 한도 안으로 줄이고 줄였다는 사실을 본문에 남긴다.
#
#   - 실제 전송과 같은 직렬화기(Yajl)로 크기를 잰다.
#   - 가장 큰 문자열 필드부터 필요한 만큼만 줄인다. level/message/exception_class 같은 작은 필드는 그대로 남는다.
#   - 머리(예외 종류·첫 frame)와 꼬리(마지막 Caused by·root cause)를 남기고 가운데를 생략한다.
#     stack_trace는 생략 구간의 "Caused by:" 줄을 따로 모아 원인 사슬을 보존한다.
#   - 줄였으면 log_truncated: {original_bytes, fields: {필드: 원래 bytes}}를 붙인다.

require "yajl"

module LeafyLogSize
  MARKER = "\n...[log_truncated: %d bytes omitted]...\n".freeze
  MIN_KEEP = 4096       # 한 필드를 이보다 작게 줄이지 않는다
  MAX_ROUNDS = 8

  module_function

  # body(Hash)를 max_bytes 안으로 맞춘다. 고친 Hash를 돌려준다 (작으면 그대로).
  def fit(body, max_bytes)
    original = Yajl.dump(body).bytesize
    return body if original <= max_bytes

    body = body.dup
    fields = {}
    # 표시도 line 크기에 들어가므로 먼저 넣고 잰다 (fields는 같은 Hash를 갱신)
    body["log_truncated"] = { "original_bytes" => original, "fields" => fields }
    MAX_ROUNDS.times do
      excess = Yajl.dump(body).bytesize - max_bytes
      break if excess <= 0
      key, value = body.select { |_, v| v.is_a?(String) && v.bytesize > MIN_KEEP }.max_by { |_, v| v.bytesize }
      break unless key
      # 이스케이프(\n, \", \t …)로 직렬화 크기가 원문보다 크므로 비율로 환산한다
      ratio = (Yajl.dump(value).bytesize - 2).fdiv(value.bytesize)
      target = ((value.bytesize * ratio - excess - MARKER.bytesize - 64) / ratio).floor
      fields[key] ||= value.bytesize
      body[key] = shrink(value, [target, MIN_KEEP].max, key == "stack_trace")
    end

    # 문자열이 아닌 큰 값(거대한 배열·객체)만 남은 드문 경우: 직렬화한 머리만 message로 남긴다
    if Yajl.dump(body).bytesize > max_bytes
      head = Yajl.dump(body).byteslice(0, max_bytes / 2).scrub("")
      body = { "message" => head, "log_truncated" => { "original_bytes" => original, "fallback" => "whole_body" } }
    end
    body
  end

  # budget bytes 안팎으로 줄인다: 머리 2/3 + 꼬리 1/3. stack이면 "Caused by:" 줄(예산의 1/4까지)을 생략 표시 뒤에 붙인다.
  # 머리·꼬리에 이미 있는 Caused by 줄이 한 번 더 나올 수 있다 (원인 사슬을 빠짐없이 남기는 쪽을 택했다).
  def shrink(value, budget, stack)
    causes = ""
    if stack
      causes = value.scrub("").each_line.select { |line| line.start_with?("Caused by:") }.join
      causes = causes.byteslice(0, budget / 4).scrub("")
    end
    rest = budget - causes.bytesize
    head = value.byteslice(0, rest * 2 / 3).scrub("")
    tail = value.byteslice(value.bytesize - rest / 3, rest / 3).scrub("")
    omitted = value.bytesize - head.bytesize - tail.bytesize
    head + format(MARKER, omitted) + causes + tail
  end
end
