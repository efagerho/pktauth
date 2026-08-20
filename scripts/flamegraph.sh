#!/usr/bin/env bash
# Flamegraph of the server process under a paced blast, with a real client
# pinging throughout so the profile covers the same workload the latency
# numbers were measured under.
#
# Needs perf, and the binaries built with frame pointers and debug info:
#   CARGO_PROFILE_RELEASE_DEBUG=true RUSTFLAGS="-C force-frame-pointers=yes" \
#     cargo build --release
# Rust symbols use the v0 mangling that perf does not decode, so the folded
# stacks go through rustfilt: cargo install rustfilt inferno
#
# Usage: scripts/flamegraph.sh <on|off> [pps]
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/common.sh

MODE=${1:?usage: flamegraph.sh <on|off> [pps]}
RATE=${2:-250000}
SECS="${SECS:-20}"; FREQ="${FREQ:-2999}"; THREADS="${THREADS:-8}"
OUT=docs; mkdir -p "$OUT"

wait_for_port_free || exit 1
rm -f server_cert.der
EXTRA=""; [ "$MODE" = off ] && EXTRA="--no-dcid-validation"
taskset -c "$SRV_CPUS" "$BIN/server" --listen "$LISTEN" $EXTRA > /tmp/flame-srv.log 2>&1 &
SPID=$!
wait_for_server /tmp/flame-srv.log || exit 1

taskset -c "$BL_CPUS" "$BIN/blaster" --target "$LISTEN" --threads "$THREADS" \
  --duration $((SECS+10)) --pps "$RATE" > /tmp/flame-blaster.log 2>&1 & BPID=$!
taskset -c "$CLI_CPUS" "$BIN/client" --server "$LISTEN" --count $(((SECS+10)*100)) \
  --interval-ms 10 --size 64 > /tmp/flame-cli.log 2>&1 & CPID=$!
disown $BPID $CPID 2>/dev/null || true
sleep 3   # reach steady state before sampling

perf record -F "$FREQ" -g --call-graph fp -p $SPID -o "/tmp/perf-$MODE.data" -- sleep "$SECS"

kill -9 $CPID $BPID 2>/dev/null; sleep 0.5
stop_server

label=$([ "$MODE" = on ] && echo ON || echo OFF)
perf script -i "/tmp/perf-$MODE.data" | rustfilt | inferno-collapse-perf > "/tmp/folded-$MODE.txt"
inferno-flamegraph \
  --title "pktauth server @ $((RATE/1000))k pps — DCID filter $label" \
  --subtitle "perf ${FREQ}Hz, ${SECS}s, server process only" \
  --colors rust --hash "/tmp/folded-$MODE.txt" > "$OUT/flamegraph-dcid-$MODE.svg"

echo "wrote $OUT/flamegraph-dcid-$MODE.svg"
grep 'udp packets' /tmp/flame-srv.log
