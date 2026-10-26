#!/bin/sh
##! Zeek 기동 래퍼 — 관측 인터페이스를 "이름"이 아니라 "서브넷"으로 찾는다.
##!
##! backend 는 multi-homed(leafy-net + mgmt-net)이고, Docker 가 붙여 주는 인터페이스
##! 이름(eth0/eth1)의 순서는 컨테이너를 다시 만들 때마다 바뀔 수 있다. 실제로 이 순서가
##! 뒤바뀌어 `-i eth0` 이 mgmt-net 을 잡은 적이 있다. 그때 Zeek 는 prometheus 스크랩만
##! 관측하고 정작 봐야 할 leafy-net 전송(backend -> sink)은 conn.log 에 한 건도 남기지
##! 못했다 (경보 0건 -> S2 미탐).
##!
##! 그래서 이름을 하드코딩하지 않고, OBSERVE_SUBNET 이 붙어 있는 인터페이스를
##! /proc/net/route 에서 찾아 쓴다. leafy-net 대역은 docker-compose.yml 에서
##! 10.210.0.0/24 로 고정돼 있으므로 이 기준은 안정적이다.
##!
##! 서브넷을 가진 인터페이스를 못 찾으면 "조용히 잘못된 NIC 를 관측" 하지 않고 즉시
##! 실패한다. 관측 경로가 틀린 채로 도는 것이 가장 위험하기 때문이다.

set -eu

OBSERVE_SUBNET="${OBSERVE_SUBNET:-10.210.0.0}"
LOG_DIR="${ZEEK_LOG_DIR:-/zeek-logs}"
ZEEK_SCRIPT="${ZEEK_SCRIPT:-/opt/observer/local.zeek}"
# 찾아낸 인터페이스 이름을 enricher 에게 넘기는 파일. enricher 의
# ZEEK_CAPTURE_IFACE_FILE 과 같은 경로를 가리켜야 한다.
IFACE_FILE="${ZEEK_CAPTURE_IFACE_FILE:-$LOG_DIR/capture-interface}"

# /proc/net/route 의 Destination 은 리틀엔디언 16진수다. 점표기 서브넷을 같은 표기로
# 바꿔 비교한다 (예: 10.210.0.0 -> 0000D20A).
iface=$(awk -v subnet="$OBSERVE_SUBNET" '
    BEGIN {
        split(subnet, o, ".")
        target = sprintf("%02X%02X%02X%02X", o[4], o[3], o[2], o[1])
    }
    $2 == target { print $1; exit }
' /proc/net/route)

if [ -z "$iface" ]; then
    echo "[start-zeek] $OBSERVE_SUBNET 을(를) 가진 인터페이스를 찾지 못했다." >&2
    echo "[start-zeek] /proc/net/route 내용:" >&2
    cat /proc/net/route >&2
    exit 1
fi

echo "[start-zeek] capture interface=$iface (subnet=$OBSERVE_SUBNET)"
cd "$LOG_DIR"

# 찾아낸 이름을 공유 볼륨에 남긴다. enricher 는 netns 가 달라 인터페이스를 직접 조회할 수
# 없고, 이름은 지금(기동 시점)에야 정해지므로 compose 의 정적 환경변수로도 전달할 수 없다.
# enricher 가 이 파일을 읽어 Canonical Event 의 interface 필드에 "실제" 값을 적는다.
# (enricher/capture.py — 없으면 null 로 기록한다)
printf '%s\n' "$iface" > "$IFACE_FILE" || \
    echo "[start-zeek] 경고: $IFACE_FILE 기록 실패 — interface 필드가 null 로 남는다" >&2

# -C : Docker 가상 NIC 는 checksum offload 를 쓰므로 체크섬 검증을 끈다. 없으면 Zeek 이
#      패킷을 무시해 conn_state=OTH, bytes=0 만 남는다 (ZEEK_DOCKER_DESKTOP_NOTES.md).
exec zeek -C -i "$iface" "$ZEEK_SCRIPT"
