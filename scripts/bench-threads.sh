#!/usr/bin/env bash
# Blaster thread scaling: how many sender threads it takes to reach the highest
# packet rate the server actually receives.
#
# Reports the rate the blaster claims alongside the rate the kernel delivered.
# The two diverge sharply once the receive queue fills, because a loopback
# send() into a full queue is *cheaper* than a real delivery: the blaster's own
# counter keeps climbing while almost nothing arrives.
#
# Usage: scripts/bench-threads.sh [thread-counts...]
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/common.sh

DUR="${DUR:-8}"; REPS="${REPS:-2}"; HZ=100
THREADS=("${@:-1 2 4 6 8 10 12 16 20 24 32 40}")
read -ra THREADS <<< "${THREADS[*]}"

wait_for_port_free || exit 1
rm -f server_cert.der
taskset -c "$SRV_CPUS" "$BIN/server" --listen "$LISTEN" > /tmp/bench-threads-srv.log 2>&1 &
SPID=$!
trap stop_server EXIT
wait_for_server /tmp/bench-threads-srv.log || exit 1

printf "%-8s %-4s %12s %12s %12s %10s\n" threads rep sent_pps deliv_pps dropped_pps srv_cores
for t in "${THREADS[@]}"; do
  for r in $(seq "$REPS"); do
    i0=$(udp_in); d0=$(sock_drops); c0=$(cputime $SPID)
    out=$(taskset -c "$BL_CPUS" "$BIN/blaster" --target "$LISTEN" --threads "$t" --duration "$DUR")
    i1=$(udp_in); d1=$(sock_drops); c1=$(cputime $SPID)
    printf "%-8s %-4s %12s %12s %12s %10s\n" "$t" "$r" \
      "$(grep -oP '^\K[0-9]+(?= packets/s,)' <<<"$out")" \
      "$(( (i1-i0)/DUR ))" "$(( (d1-d0)/DUR ))" \
      "$(awk -v a="$c0" -v b="$c1" -v d="$DUR" -v hz=$HZ 'BEGIN{printf "%.3f",(b-a)/hz/d}')"
  done
done
