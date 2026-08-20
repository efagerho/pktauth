# Shared configuration for the benchmark scripts.
#
# The server, the client and the blaster are pinned to disjoint core sets. This
# matters: without pinning, adding blaster threads steals CPU from the server
# they are aimed at, and the server's CPU figure stops being its own cost.
BIN="${BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release}"
SRV_CPUS="${SRV_CPUS:-0-3}"     # server: 4 cores, more than it was ever seen to use
CLI_CPUS="${CLI_CPUS:-4-5}"
BL_CPUS="${BL_CPUS:-8-47}"      # blaster: disjoint from both
LISTEN="${LISTEN:-127.0.0.1:4433}"

# utime+stime of a pid, in clock ticks.
cputime() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
uptime_s() { awk '{print $1}' /proc/uptime; }
# Datagrams the kernel delivered into a socket (i.e. not dropped).
udp_in() { awk '/^Udp: [0-9]/{print $2}' /proc/net/snmp; }
# Drop counter of the server's own socket.
sock_drops() { ss -uanm 2>/dev/null | grep -A1 "$LISTEN" | grep -oP 'd\K[0-9]+(?=\))'; }

# A previous run's server may still hold the port when scripts are chained.
wait_for_port_free() {
  for _ in $(seq 100); do
    ss -lun 2>/dev/null | grep -q "$LISTEN" || return 0
    sleep 0.1
  done
  echo "port $LISTEN is still bound; is another server running?" >&2
  return 1
}

wait_for_server() {
  local log=$1
  for _ in $(seq 100); do
    grep -q "listening on" "$log" && return 0
    kill -0 "$SPID" 2>/dev/null || break     # it exited; the log says why
    sleep 0.1
  done
  echo "server never came up:" >&2; sed 's/^/  /' "$log" >&2
  return 1
}

# Stops the server and waits for it to release the port, so a run that follows
# in the same shell does not race it.
stop_server() {
  kill -INT "$SPID" 2>/dev/null
  for _ in $(seq 50); do kill -0 "$SPID" 2>/dev/null || return 0; sleep 0.1; done
  kill -9 "$SPID" 2>/dev/null
}
