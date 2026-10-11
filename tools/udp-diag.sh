#!/usr/bin/env bash
# Find where a VoIPC server's UDP packets get lost. Run it on the server host
# as root while someone probes the server from outside; it changes nothing and
# writes only a pcap and a report under /tmp.
#
# The page and /wt.json work over TCP while every QUIC handshake times out, so
# UDP dies somewhere between the client and the server process. This narrows it
# down to the process, the host's own filters, or something in front of the
# host (provider firewall or anti-DDoS, hypervisor), and says which. Outside
# TCP and ping probes are captured too: without them, an empty capture proves
# nothing.
#
# Usage:  sudo tools/udp-diag.sh [port=9987] [seconds=60]
#         IP=1.2.3.4 overrides the address taken from the UDP listener.
set -u
umask 077  # root writes the report and the pcap: firewall rules, client IPs

PORT="${1:-9987}"
SECS="${2:-60}"
[ "$(id -u)" -eq 0 ] || { echo "run as root (tcpdump, nft and ss -p need it)" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump missing (apt install tcpdump)" >&2; exit 1; }

STAMP=$(date -u +%Y%m%d-%H%M%S)
REPORT=/tmp/udp-diag-$STAMP.txt
# Debian's AppArmor profile for tcpdump only lets it write *.pcap files.
PCAP=/tmp/udp-diag-$STAMP.pcap

section() { printf '\n=== %s\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1 | sed 's/^/  /'; }
have() { command -v "$1" >/dev/null 2>&1; }
count() { tcpdump -nn -r "$PCAP" "$1" 2>/dev/null | wc -l; }
udp_counters() {
  nstat -asz 2>/dev/null | awk '$1 ~ /^Udp(InDatagrams|NoPorts|InErrors|RcvbufErrors)$/ { print $1, $2 }'
}

main() {
  section "Host"
  date -u
  grep -h '^PRETTY_NAME=' /etc/os-release
  echo "kernel: $(uname -r)"
  have systemd-detect-virt && echo "virtualization: $(systemd-detect-virt)"

  section "Listener on port $PORT"
  local udp_listen tcp_listen bind
  udp_listen=$(ss -Hulpn "sport = :$PORT")
  tcp_listen=$(ss -Htlpn "sport = :$PORT")
  echo "udp: ${udp_listen:-NOTHING LISTENS}"
  echo "tcp: ${tcp_listen:-NOTHING LISTENS}"
  bind=$(awk 'NR == 1 { print $4 }' <<<"$udp_listen")
  bind=${bind%:*}; bind=${bind#[}; bind=${bind%]}
  case "$bind" in
    '' | '*' | 0.0.0.0 | ::)
      IP=${IP:-$(ip -4 route get 1.1.1.1 | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')} ;;
    *) IP=${IP:-$bind} ;;
  esac
  local url_ip=$IP fam=-4
  [[ $IP == *:* ]] && { url_ip="[$IP]"; fam=-6; }
  echo "target address: $IP"
  if have curl && curl -V | grep -q HTTP3; then
    # A plain GET is no WebTransport request: the server answers it with a 404
    # or closes the connection (curl exit 56). Only a timeout means no answer.
    local code rc
    code=$(curl --http3-only -sk -m 5 -o /dev/null -w '%{http_code}' "https://$url_ip:$PORT/voipc")
    rc=$?
    case $rc in
      0 | 56) echo "self-probe over loopback: the server answers QUIC (HTTP $code, curl exit $rc)" ;;
      28) echo "self-probe over loopback: NO answer within 5 s" ;;
      *) echo "self-probe over loopback: curl exit $rc" ;;
    esac
  fi

  section "Network"
  run ip -br addr
  run ip route
  run ip rule
  run ip neigh
  local iface gw
  iface=$(ip -o addr show | awk -v ip="$IP" '{ split($4, a, "/"); if (a[1] == ip) { print $2; exit } }')
  if [ -n "$iface" ]; then
    echo "$IP is on $iface, MAC $(cat "/sys/class/net/$iface/address"), MTU $(cat "/sys/class/net/$iface/mtu")"
    have ethtool && ethtool -S "$iface" 2>/dev/null | grep -iE 'drop|discard|err' | grep -v ': 0$' | sed 's/^/  nic counter:/'
  else
    echo "$IP is not configured on any interface here"
  fi
  gw=$(ip -4 route show default | awk '{ print $3; exit }')
  case "$gw" in
    10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*)
      echo "default gateway $gw is private: a router or firewall VM sits in front of this host, and its rules are a suspect" ;;
  esac

  section "Local packet filters"
  have nft && run nft list ruleset
  have iptables-save && run iptables-save
  have iptables-legacy-save && run iptables-legacy-save
  have ufw && run ufw status verbose
  local s
  for s in nftables ufw firewalld fail2ban crowdsec docker podman; do
    [ "$(systemctl is-active "$s" 2>/dev/null)" = active ] && echo "active service: $s"
  done
  run sysctl net.ipv4.conf.all.rp_filter net.ipv4.ip_forward net.ipv6.bindv6only
  [ -n "$iface" ] && run sysctl "net.ipv4.conf.$iface.rp_filter"

  section "Capture"
  local counters_before rx_before=0 dns dns_ok
  counters_before=$(udp_counters)
  [ -n "$iface" ] && rx_before=$(cat "/sys/class/net/$iface/statistics/rx_dropped")
  tcpdump -ni any -U -w "$PCAP" "udp or icmp or icmp6 or tcp port $PORT" 2>/dev/null &
  td=$!  # global: the EXIT trap needs it after main returns
  # A background job of a script ignores SIGINT, so Ctrl+C would leave it running.
  trap 'kill "$td" 2>/dev/null' EXIT
  sleep 1
  kill -0 "$td" 2>/dev/null || { echo "tcpdump did not start"; exit 1; }
  cat <<EOF
Capturing for $SECS s (Enter ends it early). From a machine OUTSIDE this
host's network, run now:
  curl $fam --http3-only -sk -m 8 -o /dev/null -w '%{http_code}\n' https://$url_ip:$PORT/voipc
  curl $fam -sk -m 8 -o /dev/null -w '%{http_code}\n' https://$url_ip:$PORT/wt.json
  ping -c 3 $IP
  bash -c 'echo probe > /dev/udp/$IP/$((PORT + 1))'
For the first curl, any result but a timeout (exit 28) means the handshake works.
EOF
  # Our own DNS query: does any UDP reach this host, even as a reply?
  dns=$(timeout 4 bash -c 'exec 3<>/dev/udp/1.1.1.1/53 &&
    printf "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01" >&3 &&
    head -c 2 <&3 | od -An -tx1' 2>/dev/null)
  dns_ok=0
  [[ $dns == *"12 34"* ]] && dns_ok=1
  [ "$dns_ok" -eq 1 ] && echo "own DNS query to 1.1.1.1: reply received" || echo "own DNS query to 1.1.1.1: NO reply"
  local started
  started=$(date -u +%T)
  if [ -t 0 ]; then read -r -t "$SECS" _ || true; else sleep "$SECS"; fi
  kill "$td" 2>/dev/null
  wait "$td" 2>/dev/null
  trap - EXIT
  echo "capture window: $started - $(date -u +%T) UTC"

  echo "UDP counters during the window:"
  paste <(echo "$counters_before") <(udp_counters) | awk '{ printf "  %-16s +%d\n", $1, $4 - $2 }'
  [ -n "$iface" ] && echo "  $iface rx_dropped +$(( $(cat "/sys/class/net/$iface/statistics/rx_dropped") - rx_before ))"

  section "What arrived"
  local udp_in udp_out wrong_src other_udp dns_in tcp_in icmp_in
  udp_in=$(count "dst host $IP and udp dst port $PORT")
  udp_out=$(count "udp src port $PORT and not dst host $IP")
  wrong_src=$(count "udp src port $PORT and not src host $IP and not dst host $IP")
  other_udp=$(count "dst host $IP and udp and not port $PORT and not port 53")
  dns_in=$(count "src host 1.1.1.1 and udp src port 53")
  tcp_in=$(count "dst host $IP and tcp dst port $PORT")
  icmp_in=$(count "dst host $IP and (icmp or icmp6)")
  echo "UDP in to $PORT:              $udp_in"
  echo "UDP out from $PORT (replies): $udp_out ($wrong_src from another source than $IP)"
  echo "UDP in to other ports:        $other_udp (NTP replies count too)"
  echo "DNS replies from 1.1.1.1:     $dns_in"
  echo "TCP in to $PORT (control):    $tcp_in"
  echo "ICMP in:                      $icmp_in (provider monitoring pings count too)"
  if [ "$((udp_in + udp_out))" -gt 0 ]; then
    echo "first packets on UDP $PORT:"
    tcpdump -nn -r "$PCAP" -c 6 "udp port $PORT" 2>/dev/null | sed 's/^/  /'
  fi

  section "Verdict"
  if [ -z "$udp_listen" ]; then
    echo "Nothing listens on UDP $PORT. Start the server, or check udp_port in server.toml."
  elif [ "$udp_in" -gt 0 ] && [ "$udp_out" -eq 0 ]; then
    echo "UDP $PORT reaches this host, but the server never answers. A local filter drops it"
    echo "before the socket (see 'Local packet filters'), or the server is bound to another"
    echo "address than $IP."
  elif [ "$udp_in" -gt 0 ] && [ "$wrong_src" -gt 0 ]; then
    echo "Replies leave from a source other than $IP. Set host = \"$IP\" in server.toml."
  elif [ "$udp_in" -gt 0 ]; then
    echo "UDP $PORT arrives and the server answers from $IP. The replies get lost after they"
    echo "leave this host: hypervisor or provider egress, or the client's own network."
  elif [ "$tcp_in" -eq 0 ]; then
    echo "The capture saw no outside probe: not even the TCP one (wt.json) arrived. Run the"
    echo "probes during the window, from outside, against $IP."
  else
    echo "TCP arrives, UDP $PORT never reaches this host: it is dropped in front of it."
    if [ "$((dns_ok + dns_in + other_udp))" -gt 0 ]; then
      echo "Some UDP does arrive (DNS reply or other ports), so whatever drops it is selective."
    else
      echo "No UDP arrives at all, not even the reply to this host's own DNS query."
    fi
    cat <<EOF

Next, find out whether the packets reach the hypervisor. On ESXi, in an SSH
shell, while the outside probes run again (Ctrl+C stops each capture; check the
flag names with pktcap-uw -h, the uplinks with esxcli network nic list):
  pktcap-uw --uplink vmnic0 --dir 0 --proto 0x11 --dstport $PORT -o /tmp/uplink.pcap
  net-stats -l     # this VM's switchport ID
  pktcap-uw --switchport <ID> --dir 1 --proto 0x11 --dstport $PORT -o /tmp/vm.pcap
  tcpdump-uw -nr /tmp/uplink.pcap; tcpdump-uw -nr /tmp/vm.pcap
- Nothing on the uplink: the provider drops it. At OVH, check that the Edge
  Network Firewall entry you edited is the one for $IP (every IP has its own),
  and the IP's mitigation state in the Network Security Dashboard.
- On the uplink, not on the switchport: ESXi drops it (Distributed vSwitch
  traffic filtering, NSX, the vNIC on the wrong port group).
- On the switchport, not in this capture: the vNIC or the guest driver.
EOF
  fi
  printf '\nreport: %s\npcap:   %s\n' "$REPORT" "$PCAP"
}

main 2>&1 | tee "$REPORT"
