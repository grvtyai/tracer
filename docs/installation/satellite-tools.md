# Satellite Tool Dependencies

The Satellite requires several external Linux tools to be installed for scanner plugins to be available. Missing tools cause the plugin to show `available: false` in the `/capabilities` response — the Satellite still starts and runs, but that plugin is disabled.

## Required Tools

| Tool | Plugin(s) | Purpose |
|---|---|---|
| `nmap` | nmap | Port scanning, OS detection, service version detection |
| `arp-scan` | arp-scan | Local network host discovery via ARP |
| `naabu` | naabu | Fast port discovery (alternative to nmap for large ranges) |
| `httpx` | httpx | HTTP probing, title/tech detection |
| `zgrab2` | zgrab2 | Protocol banner grabbing (TLS, SSH, FTP, ...) |
| `testssl.sh` | testssl | TLS/SSL configuration and vulnerability testing |
| `scamper` | scamper | Traceroute, path analysis |
| `zeek` | zeek | Network traffic analysis (passive) |
| `avahi-daemon` / `avahi-browse` | avahi | mDNS/Bonjour host discovery |
| `snmpwalk` | snmp | SNMP enumeration |
| LDAP tools | ldap | LDAP/AD enumeration |

## Installation (Ubuntu / Debian)

Run the provided script:

```bash
bash scripts/install-ubuntu-tools.sh
```

Or install manually:

```bash
# Core tools from apt
sudo apt-get install -y nmap arp-scan avahi-utils snmp ldap-utils

# Tools installed via Go
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# zgrab2
go install -v github.com/zmap/zgrab2@latest

# testssl.sh
sudo apt-get install -y testssl.sh
# or from git:
# git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# scamper
sudo apt-get install -y scamper

# zeek
# Zeek has its own repo — see https://docs.zeek.org/en/stable/install.html
```

## Privilege Requirements

Most tools require root or elevated privileges to run raw sockets (arp-scan, nmap SYN scan, scamper). The Satellite binary itself should be run as root or with the required capabilities:

```bash
sudo ./startrace-satellite
```

Or use Linux capabilities instead of full root:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./startrace-satellite
```

## Verifying Tool Availability

After starting the Satellite, check the capabilities endpoint:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8765/capabilities | jq '.plugins[] | {name, available, reason}'
```

Any plugin with `available: false` will include a `reason` field explaining why (usually "binary not found" or "permission denied").
