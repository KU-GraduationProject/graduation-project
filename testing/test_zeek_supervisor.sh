#!/bin/sh
# No Docker, real Zeek, real route table or network calls. Only temporary fixtures.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
pid=""
cleanup() {
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" || true; fi
    # mktemp is the only source of this path; never delete workspace paths.
    rm -rf "$fixture"
}
trap cleanup EXIT
mkdir -p "$fixture/bin" "$fixture/sys/eth1" "$fixture/sys/eth2"
cat > "$fixture/bin/zeek" <<'EOF'
#!/bin/sh
echo "$*" >> "$ZEEK_LOG_DIR/starts"
trap 'exit 0' TERM INT
while :; do sleep .1; done
EOF
chmod +x "$fixture/bin/zeek"
export PATH="$fixture/bin:$PATH"
export ZEEK_LOG_DIR="$fixture" ZEEK_ROUTE_FILE="$fixture/routes" ZEEK_SYS_NET="$fixture/sys"
export ZEEK_RECHECK_SEC=.1
echo 4 > "$fixture/sys/eth1/ifindex"
echo 5 > "$fixture/sys/eth2/ifindex"
echo 'eth1 0000D20A 0 0 0 0 0 00FFFFFF' > "$fixture/routes"
sh "$ROOT/aiops/network-observer/zeek/start-zeek.sh" > "$fixture/output" 2>&1 &
pid=$!
wait_value() {
    count=0
    while [ "$(cat "$fixture/capture-interface" 2>/dev/null || true)" != "$1" ]; do
        count=$((count+1)); [ "$count" -lt 100 ] || { cat "$fixture/output"; exit 1; }
        sleep .1
    done
}
wait_value eth1
: > "$fixture/routes"
wait_value ''
echo 'eth2 0000D20A 0 0 0 0 0 00FFFFFF' > "$fixture/routes"
wait_value eth2
# Same NIC name, new ifindex: must restart capture too.
echo 6 > "$fixture/sys/eth2/ifindex"
count=0
while [ "$(wc -l < "$fixture/starts")" -lt 3 ]; do
    count=$((count+1)); [ "$count" -lt 100 ] || exit 1
    sleep .1
done
echo 'PASS: subnet loss, reconnect NIC change, same-name ifindex replacement'
