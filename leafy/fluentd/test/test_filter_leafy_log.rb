# plugins/filter_leafy_docker_log.rb, filter_leafy_postgres_log.rb 단위 테스트
#
# 실행 (저장소 루트, Fluentd 이미지 안에서):
#   docker build -t leafy-fluentd-test leafy/fluentd
#   docker run --rm -v "$PWD/leafy/fluentd/test:/test:ro" --entrypoint ruby leafy-fluentd-test \
#     -I/fluentd/plugins /test/test_filter_leafy_log.rb

require "test/unit"
require "fluent/test"
require "fluent/test/driver/filter"
require "fluent/test/helpers"
require "filter_leafy_docker_log"
require "filter_leafy_postgres_log"
require "yajl"

class LeafyDockerLogFilterTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
  end

  def filter(records, tag: "backend")
    d = Fluent::Test::Driver::Filter.new(Fluent::Plugin::LeafyDockerLogFilter).configure("")
    t = event_time("2026-10-23 05:01:02.123456789 UTC")
    d.run(default_tag: tag) { records.each { |r| d.feed(t, r) } }
    d.filtered.map { |time, rec| [time, rec] }
  end

  def docker(log, extra = {})
    {
      "container_id" => "c0ffee" * 10 + "abcd",
      "container_name" => "/leafy-backend",
      "source" => "stdout",
      "log" => log,
      "com.docker.compose.service" => "backend",
    }.merge(extra)
  end

  test "JSON 로그는 앱 필드를 그대로(순서 유지) 본문으로 쓰고 docker 메타데이터를 덧붙인다" do
    app = {
      "@timestamp" => "2026-10-23T14:01:02.123+09:00",
      "level" => "ERROR",
      "message" => "login failed",
      "http_method" => "POST",
      "status" => 401,
      "request_id" => "r-1",
      "stack_trace" => "java.lang.IllegalStateException: x\n\tat com.leafy.A.b(A.java:1)",
    }
    time, rec = filter([docker(JSON.generate(app))]).first

    assert_equal event_time("2026-10-23 05:01:02.123456789 UTC"), time # 시각은 바꾸지 않는다
    body = rec.reject { |k, _| k.start_with?("_lbl_") }
    assert_equal app.keys + ["docker"], body.keys
    assert_equal app, body.reject { |k, _| k == "docker" }
    assert_equal "2026-10-23T14:01:02.123+09:00", body["@timestamp"] # offset 보존
    assert_equal 401, body["status"]                                  # 숫자 타입 보존
    assert_equal({ "container_id" => "c0ffee" * 10 + "abcd", "container_name" => "/leafy-backend",
                   "source" => "stdout", "com.docker.compose.service" => "backend" }, body["docker"])
    assert_equal({ "_lbl_container" => "backend", "_lbl_source" => "stdout", "_lbl_service" => "backend",
                   "_lbl_container_name" => "leafy-backend", "_lbl_runtime" => "container",
                   "_lbl_log_format" => "json" }, rec.select { |k, _| k.start_with?("_lbl_") })
  end

  test "Nginx JSON의 time 문자열과 문자열 status를 건드리지 않는다" do
    line = '{"time":"2026-10-23T14:01:02+09:00","request_method":"GET","request_uri":"/api/x?id=1","status":"502"}'
    _, rec = filter([docker(line, "container_name" => "/leafy-frontend",
                                  "com.docker.compose.service" => "frontend")], tag: "frontend").first
    assert_equal "2026-10-23T14:01:02+09:00", rec["time"]
    assert_equal "502", rec["status"]
    assert_equal "frontend", rec["_lbl_service"]
  end

  test "텍스트 로그는 원문을 message에 담는다 (앞 공백 유지, 끝 개행 제거)" do
    _, rec = filter([docker("\tat com.leafy.A.b(A.java:1)\r\n")]).first
    assert_equal "\tat com.leafy.A.b(A.java:1)", rec["message"]
    assert_equal "text", rec["_lbl_log_format"]
    assert_false rec.key?("log_parse_error")
  end

  test "{로 시작하지만 깨진 JSON은 json_invalid로 원문과 오류를 보존한다" do
    truncated = '{"level":"ERROR","message":"' + "x" * 50
    _, rec = filter([docker(truncated)]).first
    assert_equal truncated, rec["message"]
    assert_equal "json_invalid", rec["_lbl_log_format"]
    assert_kind_of String, rec["log_parse_error"]
    assert_operator rec["log_parse_error"].size, :<=, 200
  end

  test "객체가 아닌 JSON 값도 버리지 않는다" do
    recs = filter([docker("123"), docker('"str"'), docker("[1,2]"), docker("null")])
    assert_equal ["123", '"str"', "[1,2]", "null"], recs.map { |_, r| r["message"] }
    assert_equal ["text"] * 4, recs.map { |_, r| r["_lbl_log_format"] }
  end

  test "timeout으로 방출된 partial 레코드는 incomplete로 표시하고 partial 메타데이터를 남긴다" do
    rec_in = docker('{"level":"ERROR","message":"' + "y" * 100,
                    "partial_message" => "true", "partial_id" => "p1", "partial_ordinal" => "1", "partial_last" => "false")
    _, rec = filter([rec_in]).first
    assert_true rec["log_partial_incomplete"]
    assert_equal "json_invalid", rec["_lbl_log_format"]
    assert_equal "p1", rec["docker"]["partial_id"]
  end

  test "compose 라벨/container 메타데이터가 없으면 unknown, container_name label은 nil" do
    _, rec = filter([{ "log" => "hello" }], tag: "minio").first
    assert_equal "unknown", rec["_lbl_service"]
    assert_equal "unknown", rec["_lbl_runtime"]
    assert_nil rec["_lbl_container_name"]
    assert_equal "stdout", rec["_lbl_source"]
    assert_equal({}, rec["docker"])
  end

  test "log 키가 없는 레코드도 다른 필드를 보존한다" do
    _, rec = filter([{ "message" => "from other forwarder", "source" => "stderr" }]).first
    assert_equal "", rec["message"]
    assert_equal({ "message" => "from other forwarder", "source" => "stderr" }, rec["docker"])
  end

  test "잘못된 UTF-8 바이트는 치환하고 예외를 내지 않는다" do
    _, rec = filter([docker("bad \xFF\xFE bytes".b)]).first
    assert_true rec["message"].valid_encoding?
    # 잘못된 바이트마다 치환 문자가 하나씩 들어간다
    assert_equal "bad \uFFFD\uFFFD bytes", rec["message"]
  end

  test "앱 JSON에 docker 키가 있으면 덮어쓰지 않는다" do
    _, rec = filter([docker('{"docker":"app value"}')]).first
    assert_equal "app value", rec["docker"]
    assert_equal "/leafy-backend", rec["_docker"]["container_name"]
  end
end

class LeafyPostgresLogFilterTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  CONF = %(
    service db
    runtime host
  )

  def setup
    Fluent::Test.setup
  end

  def filter(record)
    d = Fluent::Test::Driver::Filter.new(Fluent::Plugin::LeafyPostgresLogFilter).configure(CONF)
    d.run(default_tag: "postgresql.jsonlog") { d.feed(event_time("2026-10-24 00:00:00 UTC"), record) }
    d.filtered.first
  end

  PG = {
    "timestamp" => "2026-10-23 14:01:02.123 KST",
    "user" => "leafy", "dbname" => "leafy", "pid" => 4321,
    "remote_host" => "172.17.0.1", "remote_port" => 50000,
    "error_severity" => "FATAL", "state_code" => "28P01",
    "message" => "password authentication failed for user \"leafy\"",
    "backend_type" => "client backend",
    "pg_log_file" => 'C:\Program Files\PostgreSQL\17\data\log\postgresql-2026-10-23_000000.json',
  }.freeze

  test "KST timestamp를 entry 시각으로 쓰고 원본 필드는 그대로 둔다" do
    time, rec = filter(PG)
    assert_equal event_time("2026-10-23 05:01:02.123 UTC"), time
    assert_equal PG, rec.reject { |k, _| k.start_with?("_lbl_") }
    assert_equal({ "_lbl_service" => "db", "_lbl_runtime" => "host", "_lbl_log_format" => "json" },
                 rec.select { |k, _| k.start_with?("_lbl_") })
  end

  test "UTC/GMT 약어와 숫자 offset을 지원한다" do
    assert_equal event_time("2026-10-23 14:01:02.5 UTC"), filter(PG.merge("timestamp" => "2026-10-23 14:01:02.500 UTC"))[0]
    assert_equal event_time("2026-10-23 14:01:02 UTC"), filter(PG.merge("timestamp" => "2026-10-23 14:01:02 GMT"))[0]
    assert_equal event_time("2026-10-23 05:01:02.123 UTC"), filter(PG.merge("timestamp" => "2026-10-23 14:01:02.123 +09"))[0]
    assert_equal event_time("2026-10-23 04:31:02.123 UTC"), filter(PG.merge("timestamp" => "2026-10-23 14:01:02.123 +0930"))[0]
  end

  test "모르는 약어는 추측하지 않고 수신 시각을 쓰며 표시한다" do
    time, rec = filter(PG.merge("timestamp" => "2026-10-23 14:01:02.123 CEST"))
    assert_equal event_time("2026-10-24 00:00:00 UTC"), time
    assert_equal "2026-10-23 14:01:02.123 CEST", rec["timestamp"]
    assert_match(/unsupported timestamp/, rec["log_time_parse_error"])
  end

  test "Fluent Bit이 JSON 파싱에 실패해 보낸 원문 레코드는 text로 보존한다" do
    time, rec = filter({ "log" => "{\"timestamp\":\"2026-10-23 14:0", "pg_log_file" => "x.json" })
    assert_equal event_time("2026-10-24 00:00:00 UTC"), time
    assert_equal "text", rec["_lbl_log_format"]
    assert_equal "{\"timestamp\":\"2026-10-23 14:0", rec["log"]
    assert_false rec.key?("log_time_parse_error")
  end
end

# Loki max_line_size(256KB) 초과 방지: 큰 필드만 줄이고 RCA 핵심 필드는 그대로 남는지
class LeafyLogSizeTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  LIMIT = 240 * 1024

  def setup
    Fluent::Test.setup
  end

  def docker_filter(log)
    d = Fluent::Test::Driver::Filter.new(Fluent::Plugin::LeafyDockerLogFilter).configure("")
    d.run(default_tag: "backend") do
      d.feed(event_time("2026-10-24 01:00:00 UTC"), { "container_id" => "f" * 64, "container_name" => "/leafy-backend",
                                                       "source" => "stdout", "com.docker.compose.service" => "backend",
                                                       "log" => log })
    end
    d.filtered.first[1]
  end

  def body_of(rec)
    rec.reject { |k, _| k.start_with?("_lbl_") }
  end

  # 부록B 업로드 예외와 같은 구조: 예외 + frame 수천 줄 + 중간의 Caused by + 끝의 root cause
  def huge_stack
    frames = (1..2500).map { |i| "\tat com.leafy.global.storage.FileStorageService.step#{i}(FileStorageService.java:#{i}) ~[!/:0.0.1-SNAPSHOT]" }
    (["software.amazon.awssdk.core.exception.SdkClientException: Unable to execute HTTP request: Connect to minio:9000 failed"] +
      frames[0, 1200] + ["Caused by: org.apache.http.conn.ConnectTimeoutException: Connect to minio:9000 failed: Connect timed out"] +
      frames[1200..] + ["Caused by: java.net.SocketTimeoutException: Connect timed out", "\tat java.base/java.net.Socket.connect(Socket.java:633)",
                        "\t... 197 common frames omitted"]).join("\n") + "\n"
  end

  test "작은 로그는 그대로 둔다" do
    rec = docker_filter('{"level":"INFO","message":"ok"}')
    assert_false rec.key?("log_truncated")
  end

  test "300KB+ JSON 예외 로그: 한도 안으로 줄이고 RCA 필드와 원인 사슬을 보존한다" do
    stack = huge_stack
    app = { "timestamp" => "2026-09-22T15:40:48.956+09:00", "level" => "ERROR",
            "logger" => "com.leafy.global.exception.GlobalExceptionHandler", "message" => "[UNHANDLED] POST /api/images/upload 처리 중 예외 발생",
            "request_id" => "8f14e45fceea167a5a36dedd4bea2543", "exception_class" => "software.amazon.awssdk.core.exception.SdkClientException",
            "exception_message" => "Unable to execute HTTP request: Connect to minio:9000 failed", "stack_trace" => stack }
    assert_operator Yajl.dump(app).bytesize, :>, 262_144
    rec = docker_filter(Yajl.dump(app))
    body = body_of(rec)

    assert_operator Yajl.dump(body).bytesize, :<=, LIMIT
    assert_equal "json", rec["_lbl_log_format"]
    %w[timestamp level logger message request_id exception_class exception_message].each { |k| assert_equal app[k], body[k], k }
    trace = body["stack_trace"]
    assert_true trace.start_with?(stack[0, 2000])                     # 예외 종류와 첫 frame
    assert_true trace.end_with?(stack[-200..])                        # root cause와 끝
    assert_match(/\.\.\.\[log_truncated: \d+ bytes omitted\]\.\.\./, trace)
    assert_include trace, "Caused by: org.apache.http.conn.ConnectTimeoutException"
    assert_include trace, "Caused by: java.net.SocketTimeoutException"
    assert_equal stack.bytesize, body["log_truncated"]["fields"]["stack_trace"]
    assert_operator body["log_truncated"]["original_bytes"], :>, 262_144
    assert_equal "/leafy-backend", body["docker"]["container_name"]
  end

  test "300KB+ 텍스트 줄과 멀티바이트 문자" do
    raw = "가" * 120_000 + " END"
    rec = docker_filter(raw)
    body = body_of(rec)
    assert_operator Yajl.dump(body).bytesize, :<=, LIMIT
    assert_equal "text", rec["_lbl_log_format"]
    assert_true body["message"].valid_encoding?
    assert_true body["message"].end_with?(" END")
    assert_equal raw.bytesize, body["log_truncated"]["fields"]["message"]
  end

  test "PostgreSQL 긴 statement" do
    d = Fluent::Test::Driver::Filter.new(Fluent::Plugin::LeafyPostgresLogFilter).configure("service db\nruntime host")
    msg = "duration: 250.1 ms  statement: insert into t values " + ("(1,'x')," * 50_000)
    d.run(default_tag: "postgresql.jsonlog") do
      d.feed(event_time("2026-10-24 00:00:00 UTC"), { "timestamp" => "2026-10-24 09:00:00.000 KST", "error_severity" => "LOG",
                                                       "message" => msg })
    end
    time, rec = d.filtered.first
    assert_equal event_time("2026-10-24 00:00:00 UTC"), time
    assert_operator Yajl.dump(body_of(rec)).bytesize, :<=, LIMIT
    assert_true rec["message"].start_with?("duration: 250.1 ms  statement: insert")
    assert_equal "2026-10-24 09:00:00.000 KST", rec["timestamp"]
    assert_equal "json", rec["_lbl_log_format"]
  end

  test "문자열이 아닌 거대한 값만 있으면 직렬화한 머리를 message로 남긴다" do
    body = LeafyLogSize.fit({ "items" => (1..60_000).to_a }, LIMIT)
    assert_operator Yajl.dump(body).bytesize, :<=, LIMIT
    assert_equal "whole_body", body["log_truncated"]["fallback"]
  end
end
