#!/usr/bin/env bash

set -euo pipefail

export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:/usr/local/bin:$PATH"

check_cmd() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf '[ok]   %s -> %s\n' "$name" "$(command -v "$name")"
  else
    printf '[miss] %s\n' "$name"
  fi
}

check_any() {
  local label="$1"
  shift

  local candidate
  for candidate in "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '[ok]   %s -> %s\n' "$label" "$(command -v "$candidate")"
      return 0
    fi
  done

  printf '[miss] %s\n' "$label"
}

check_cmd go
check_cmd naabu
check_cmd httpx
check_cmd nmap
check_cmd arp-scan
check_cmd avahi-browse
check_cmd zmap
check_cmd scamper
check_cmd zgrab2
check_cmd testssl.sh
check_cmd snmpwalk
check_cmd zeek
check_cmd ldapdomaindump
check_any impacket impacket-secretsdump secretsdump.py impacket-GetUserSPNs GetUserSPNs.py

if [[ -f "${HOME}/.local/share/tracer/sharphound/SharpHound-latest.zip" ]]; then
  printf '[ok]   SharpHound bundle -> %s\n' "${HOME}/.local/share/tracer/sharphound/SharpHound-latest.zip"
else
  printf '[miss] SharpHound bundle\n'
fi
