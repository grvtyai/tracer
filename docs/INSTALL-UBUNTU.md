# Ubuntu Installation

This repository includes an Ubuntu installer for the current Startrace scan and enrichment toolchain:

```bash
bash scripts/install-ubuntu-tools.sh
```

After that, verify the installation with:

```bash
bash scripts/verify-ubuntu-tools.sh
```

## What gets installed

- Go from `go.dev`
- `naabu` and `httpx` via `go install`
- `nmap`, `arp-scan`, `avahi-utils`, `snmp`, and `zmap` via `apt`
- `scamper` via Ubuntu PPA where supported
- `zgrab2` built from the official GitHub repository
- `testssl.sh` installed with its full support files
- `ldapdomaindump` and `impacket` via `pipx`
- Zeek from the official OBS repository
- SharpHound CE as a downloaded release ZIP for later use

## Important notes

- `SharpHound` is not treated as a normal Linux collector in the current Startrace flow. The script only downloads the release ZIP for convenience. For production use, align the version with the collector version shown in BloodHound CE.
- `scamper` and in some cases `naabu`, `nmap`, `zmap`, or `arp-scan` may require root privileges or capabilities depending on how they are used.
- Zeek is installed under `/opt/zeek`, so the installer extends your `PATH`.
- `testssl.sh` now installs with its supporting files under `/usr/local/share/testssl` and is exposed through `/usr/local/bin/testssl.sh` so it keeps working under `sudo`.

## Installation approach

- Confirmed primary paths:
  - Go from `go.dev`
  - `naabu` and `httpx` via Go
  - `zgrab2` from a source build
  - Zeek via the official OBS repository
- Deliberately pragmatic paths:
  - `impacket` is installed via `pipx` so the CLI stays isolated
  - `ldapdomaindump` is installed via `pipx` so the CLI stays isolated
  - `nmap`, `arp-scan`, `avahi-utils`, `snmp`, and `zmap` come from Ubuntu packages because that is the simplest and most reliable path on the VM
  - `scamper` is installed through an Ubuntu PPA in the script; that is convenient for the VM, but still worth validating against the exact Ubuntu release you plan to keep
