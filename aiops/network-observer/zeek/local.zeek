##! Network Observer - Zeek 설정 (#5)
##!
##! 목적: conn.log를 JSON Lines로 안정적으로 남겨 enricher가 tail 할 수 있게 한다.
##! Canonical Event 변환은 Zeek이 아니라 enricher가 담당한다.
##! (observer 교체 가능성을 유지하기 위해 Zeek 스크립트에 schema를 넣지 않는다.
##!  -> NETWORK_EVENT_SCHEMA.md P5 / D16)

# conn.log 등 전체 로그를 JSON으로 출력. enricher가 라인 단위로 파싱한다.
redef LogAscii::use_json = T;

# 로그 로테이션 비활성화.
# 로테이션되면 enricher가 tail 중인 파일이 교체되어 이벤트가 유실된다.
# 보존/로테이션 정책은 #8(ingestion)에서 결정한다.
redef Log::default_rotation_interval = 0 secs;

# conn.log 외의 프로토콜 로그는 이번 범위에서 사용하지 않는다.
# 비활성화하여 디스크/CPU 낭비를 줄인다. (필요해지면 #8 이후 재검토)
event zeek_init() &priority=-10
    {
    local keep: set[Log::ID] = { Conn::LOG };

    # 순회 중에 Log::active_streams를 변경하면 iterator가 무효화된다.
    # 먼저 대상을 모은 뒤 따로 비활성화한다.
    local to_disable: vector of Log::ID;

    for ( id in Log::active_streams )
        {
        if ( id !in keep )
            to_disable += id;
        }

    for ( i in to_disable )
        Log::disable_stream(to_disable[i]);
    }
