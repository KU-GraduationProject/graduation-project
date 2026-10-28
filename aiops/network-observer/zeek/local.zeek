##! Network Observer - Zeek 설정 (#5, P6)
##!
##! 목적:
##!   1) conn.log 를 JSON Lines 로 남겨 enricher 가 tail 한다 (최종 연결 집계).
##!   2) P6: 연결이 종료되기 전, originator 전송 바이트가 임계값을 넘는 순간
##!      conn_threshold.log 에 중간(조기) 이벤트를 남긴다. 저속·장시간 전송을
##!      종료 전에 탐지하기 위함이다.
##! Canonical Event 변환은 Zeek 이 아니라 enricher 가 담당한다
##!   (observer 교체 가능성 유지 -> NETWORK_EVENT_SCHEMA.md P5 / D16).

@load base/protocols/conn
# ConnThreshold 는 별도 framework 가 아니라 conn 프로토콜 스크립트에 있다 (zeek 9.0.0 기준 확인).
@load base/protocols/conn/thresholds

# conn.log 등 전체 로그를 JSON 으로 출력. enricher 가 라인 단위로 파싱한다.
redef LogAscii::use_json = T;

# 로그 로테이션 비활성화. 로테이션되면 enricher 가 tail 중인 파일이 교체되어 유실된다.
redef Log::default_rotation_interval = 0 secs;

# ─────────────────────────────────────────────────────────────────────────────
# P6: 전송 중 임계 도달 조기 이벤트 스트림
# ─────────────────────────────────────────────────────────────────────────────
module S2Threshold;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:         time    &log;
        uid:        string  &log;
        id:         conn_id &log;   # JSON 에서 id.orig_h / id.resp_p 등으로 평탄화된다
        proto:      string  &log;
        orig_bytes: count   &log;   # 임계 도달 시점까지의 originator 누적 바이트 (최종값 아님)
        threshold:  count   &log;   # 교차된 임계값
        event_kind: string  &log &default = "connection_threshold";
    };

    # originator 전송 바이트 임계값(N). redef 로 조정 가능 (Step 5/6 에서 동결).
    # ConnThreshold 는 IP 계층 바이트(헤더 포함, conn.log 의 orig_ip_bytes 기준)로 센다. 그래서
    # 로그의 orig_bytes(페이로드)는 임계값보다 약간 작게 찍힌다 (2MB 합성 pcap 에서 1020840 < 1048576 확인).
    # Loki 규칙의 min_transfer_bytes(allowlist.yml)와 함께 N·R·T 관계를 기록해 동결한다.
    const byte_threshold: count = 1048576 &redef;   # 1MB
}

# 스트림 생성. 아래 "스트림 정리" zeek_init(우선순위 -10)보다 먼저 실행되도록
# 기본 우선순위(0)로 둔다. 그리고 keep 집합에 S2Threshold::LOG 를 포함시킨다.
event zeek_init()
    {
    Log::create_stream(S2Threshold::LOG, [$columns = Info, $path = "conn_threshold"]);
    }

# 연결 수립 시 originator 방향 바이트 임계값을 1회 설정(single-shot).
event connection_established(c: connection)
    {
    ConnThreshold::set_bytes_threshold(c, S2Threshold::byte_threshold, T);
    }

# 임계 교차 시 중간 이벤트 1건 기록. 재설정하지 않으므로 연결당 1회(single-shot).
event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
    {
    if ( ! is_orig )
        return;   # originator(backend) 전송 바이트만 본다

    local proto_str = ( c?$conn && c$conn?$proto ) ? cat(c$conn$proto) : "unknown";
    local sent = ( c?$orig && c$orig?$size ) ? c$orig$size : threshold;

    Log::write(S2Threshold::LOG, [
        $ts         = network_time(),
        $uid        = c$uid,
        $id         = c$id,
        $proto      = proto_str,
        $orig_bytes = sent,
        $threshold  = threshold,
        $event_kind = "connection_threshold"
    ]);
    }

# ─────────────────────────────────────────────────────────────────────────────
# 스트림 정리: Conn::LOG 와 S2Threshold::LOG 외의 프로토콜 로그는 끈다 (디스크/CPU 절약).
# ─────────────────────────────────────────────────────────────────────────────
module GLOBAL;

event zeek_init() &priority=-10
    {
    local keep: set[Log::ID] = { Conn::LOG, S2Threshold::LOG };

    # 순회 중 Log::active_streams 를 바꾸면 iterator 가 무효화된다. 먼저 모은 뒤 끈다.
    local to_disable: vector of Log::ID;
    for ( id in Log::active_streams )
        {
        if ( id !in keep )
            to_disable += id;
        }
    for ( i in to_disable )
        Log::disable_stream(to_disable[i]);
    }
