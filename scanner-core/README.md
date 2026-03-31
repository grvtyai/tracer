# scanner-core

`scanner-core` ist das orchestrierende Herz von `tracer`.
Hier liegen das Scan-Domaenenmodell, die Job-Planung und die Plugin-Vertraege fuer externe Scanner.

## Phase 1 Fokus

- `arp-scan` fuer L2-Ground-Truth im lokalen Segment
- `naabu` als guenstige Standard-Port-Discovery
- `scamper` fuer selektive Pfadmessung
- `nmap` fuer Service- und OS-Erkennung auf bereits offenen Zielen
- JSON-Normalisierung in ein einheitliches Evidence-Modell

## Warum so starten?

Der teuerste Fehler waere, alle Werkzeuge sofort miteinander zu verheiraten und danach festzustellen, dass Ergebnisse nicht sauber korreliert werden koennen.
Dieses Geruest priorisiert deshalb:

1. gemeinsames Scope-Modell
2. explizite Pipeline-Jobs
3. normalisierte Evidence
4. spaeter austauschbare Tool-Runner

## Was als Naechstes kommt

1. Runner fuer `naabu` mit JSON-Parsing und Exit-Code-Behandlung
2. Runner fuer `nmap` mit Mapping auf `service.Fingerprint`
3. `scamper`-Normalisierung auf Routen- und Blockierungs-Evidence
4. Persistenz fuer Runs, Evidence und Diffs
