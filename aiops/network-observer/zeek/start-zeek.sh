#!/bin/sh
# Follow business subnet AND link identity across ISOLATE / RECONNECT.
# Empty capture-interface means unavailable; never fall back to management NIC.
set -eu
OBSERVE_SUBNET="${OBSERVE_SUBNET:-10.210.0.0}"
LOG_DIR="${ZEEK_LOG_DIR:-/zeek-logs}"
ZEEK_SCRIPT="${ZEEK_SCRIPT:-/opt/observer/local.zeek}"
IFACE_FILE="${ZEEK_CAPTURE_IFACE_FILE:-$LOG_DIR/capture-interface}"
ROUTE_FILE="${ZEEK_ROUTE_FILE:-/proc/net/route}"
SYS_NET="${ZEEK_SYS_NET:-/sys/class/net}"
INTERVAL="${ZEEK_RECHECK_SEC:-2}"
pid=""
identity=""
publish() { printf '%s\n' "$1" > "$IFACE_FILE.tmp"; mv "$IFACE_FILE.tmp" "$IFACE_FILE"; }
stop_capture() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    pid=""
    identity=""
    publish ""
}
trap 'stop_capture; exit 0' TERM INT
cd "$LOG_DIR"
publish ""
while :; do
    iface=$(awk -v subnet="$OBSERVE_SUBNET" '
        BEGIN { split(subnet, o, "."); target=sprintf("%02X%02X%02X%02X",o[4],o[3],o[2],o[1]) }
        $2 == target && $8 == "00FFFFFF" { print $1; exit }
    ' "$ROUTE_FILE")
    next=""
    if [ -n "$iface" ] && [ -r "$SYS_NET/$iface/ifindex" ]; then
        next="$iface:$(cat "$SYS_NET/$iface/ifindex")"
    fi
    if [ "$next" != "$identity" ] || { [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; }; then
        stop_capture
    fi
    if [ -n "$next" ] && [ -z "$pid" ]; then
        echo "[start-zeek] capture=$next subnet=$OBSERVE_SUBNET"
        zeek -C -i "$iface" "$ZEEK_SCRIPT" &
        pid=$!
        identity="$next"
        publish "$iface"
    fi
    sleep "$INTERVAL" &
    wait $! || true
done
