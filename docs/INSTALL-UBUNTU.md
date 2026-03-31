# Ubuntu Installation

Diese Repo bringt einen Ubuntu-Installer fuer die Scan-Toolchain mit:

```bash
bash scripts/install-ubuntu-tools.sh
```

Danach kannst du die Installation mit diesem Check verifizieren:

```bash
bash scripts/verify-ubuntu-tools.sh
```

## Was installiert wird

- Go von `go.dev`
- `naabu` und `httpx` via `go install`
- `nmap`, `arp-scan`, `zmap` via `apt`
- `scamper` via Ubuntu-PPA
- `zgrab2` aus dem offiziellen GitHub-Repository gebaut
- `ldapdomaindump` und `impacket` via `pipx`
- Zeek aus dem offiziellen OBS-Repository
- SharpHound CE als heruntergeladene Release-ZIP fuer spaeteren Einsatz

## Wichtige Hinweise

- `SharpHound` ist kein normaler Linux-Collector in deinem geplanten Ablauf. Das Skript laedt die Release-Datei nur bequem herunter. Fuer produktiven Einsatz solltest du die Version an die in BloodHound CE angezeigte Collector-Version anpassen.
- `scamper` und teils auch `naabu`, `nmap`, `zmap` oder `arp-scan` brauchen je nach Probe-Art Root-Rechte oder Capabilities.
- Zeek wird aus den offiziellen Paketen unter `/opt/zeek` installiert; das Skript erweitert deshalb deinen `PATH`.

## Einordnung der Installationswege

- Offiziell bestaetigt durch Quellen:
  - Go von `go.dev`
  - `naabu`/`httpx` via Go
  - `zgrab2` aus Source-Build
  - Zeek via offizielles OBS-Repo
- Bewusste pragmatische Ableitung:
  - `impacket` wird hier via `pipx` statt plain `pip` installiert, damit das CLI isoliert bleibt.
  - `ldapdomaindump` wird hier via `pipx` statt plain `pip` installiert, damit das CLI isoliert bleibt.
  - `nmap`, `arp-scan` und `zmap` werden ueber Ubuntu-Pakete installiert, weil das fuer die VM der einfachste und robusteste Weg ist.
  - `scamper` wird im Skript ueber ein Ubuntu-PPA installiert; das ist fuer die VM bequem, sollte aber auf deiner Ziel-Ubuntu-Version einmal real gegengeprueft werden.
