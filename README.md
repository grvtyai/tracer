# tracer

`tracer` wird als orchestrierendes Scan-Framework aufgebaut, nicht als Sammlung lose verklebter Wrapper.
Das Ziel ist ein normalisiertes JSON/Evidence-Modell ueber mehreren Discovery-, Routing-, Fingerprint- und AD-Audit-Werkzeugen.

## Zielbild

Die angestrebte Vollversion soll sich per Einzeiler auf Ubuntu installieren lassen und danach in zwei Modi funktionieren:

- als GUI-gestuetztes System fuer Projekte wie `Standort A`, inklusive Dashboards, Projektverwaltung, Scan-Historie und spaeteren Reevals
- als CLI-Variante fuer headless Systeme, die in dasselbe Datenmodell schreibt oder exportierbare Ergebnisse fuer die GUI erzeugt

Ein Projekt soll spaeter:

- Scopes und erlaubte Netze definieren
- wiederholbare Scans ausfuehren
- Host- und Service-Inventar aufbauen
- Erreichbarkeit, Filterung und wahrscheinliche Firewall-Effekte bewerten
- Ergebnisse ueber mehrere Runs hinweg vergleichen

## Aktueller Fokus

Die erste Ausbaustufe lebt unter `scanner-core/` und deckt das Grundgeruest fuer diese Pipeline ab:

1. Scope vorbereiten
2. L2-Discovery mit `arp-scan`, wenn lokal moeglich
3. L4-Port-Discovery mit `naabu` als Default
4. Selektives Routing mit `scamper`
5. Service- und OS-Erkennung mit `nmap`
6. Einheitliche JSON-Normalisierung und Evidence-Speicherung

## Architekturprinzipien

- Orchestrierung und Tool-Adapter sind getrennt.
- Externe Tools bleiben Source of Truth fuer ihre Spezialdomaine.
- Blockierungsdiagnostik bewertet Evidence in `confirmed`, `probable` und `ambiguous`.
- Teure Schritte laufen nur auf bereits bestaetigten Kandidaten weiter.
- Der Scanner arbeitet jetzt bewusst `fail-soft`: Teilfehler einzelner Hosts oder Plugins sollen den restlichen Run nicht abbrechen.
- Operator-Optionen werden in einem gemeinsamen `options`-Modell gehalten, damit dieselben Einstellungen spaeter sowohl per CLI als auch per GUI steuerbar sind.
- Persistenz wird lokal zunaechst ueber `SQLite` aufgebaut, damit GUI und CLI dieselbe Datenbasis nutzen koennen.

## Resilienz Und Optionen

- Ein Run liefert jetzt neben Evidence auch Job-Status fuer erfolgreiche und fehlgeschlagene Schritte.
- Bereits gefundene Evidence bleibt erhalten, auch wenn spaetere Jobs fuer einzelne Hosts fehlschlagen.
- Fehlgeschlagene oder zweifelhafte Ergebnisse koennen als Reeval-Hinweise fuer spaetere Wiederholungen markiert werden.
- Typische Operator-Einstellungen wie `active_interface`, `passive_interface`, `port_template`, `continue_on_error` oder `reevaluate_after` sind als eigene Optionen modelliert.
- Passive Sensorik wird jetzt bewusst als eigener Optionsraum modelliert, damit spaeter dieselben Einstellungen in GUI und CLI als Dropdowns/Schalter erscheinen koennen.

## Persistenzmodell

Die lokale Standardpersistenz ist jetzt bewusst auf `SQLite` ausgerichtet.
Das ist die Basis fuer:

- Projekte
- Runs
- Job-Ergebnisse
- normalisierte Evidence
- Blocking-Bewertungen
- Reeval-Hinweise

Der Speicherort soll spaeter sowohl in der GUI als auch per CLI anpassbar sein.

Wenn `tracer` unter `sudo` gestartet wird, versucht der Default-Pfad jetzt bewusst, den Datenordner des aufrufenden Operators zu verwenden statt stillschweigend nach `/root/.local/share/...` zu schreiben.
Ein explizites `--db-path` oder `--data-dir` ueberschreibt dieses Verhalten weiterhin.

## Erste SQLite-Abfragen

Die CLI kann jetzt nicht nur Runs schreiben, sondern auch gespeicherte Projekte, Runs und Unterschiede zwischen Runs als JSON ausgeben:

```bash
./bin/tracer -mode projects
./bin/tracer -mode runs --project "Standort A"
./bin/tracer -mode show-run --run-id <run-id>
./bin/tracer -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

Der Diff ist bewusst semantisch und evidence-basiert:

- `new_evidence`: im neueren Run neu aufgetaucht
- `missing_evidence`: im neueren Run nicht mehr vorhanden
- `changed_evidence`: semantisch dasselbe Artefakt, aber mit geaenderten Details wie Versionen oder HTTP-Merkmalen

## Zeek Als Bedarfssensor

`Zeek` soll nicht blind immer laufen, aber auch nicht pauschal ausgeschaltet werden.
Deshalb gibt es jetzt einen sensororientierten Modus:

- `passive_mode=off`: kein passiver Zeek-Pfad
- `passive_mode=auto`: Zeek wird nur genutzt, wenn passive Ingests sinnvoll oder konfiguriert sind; fehlende Logs brechen den Run nicht
- `passive_mode=always`: Zeek wird strikt erwartet und Fehler werden sichtbar

Zusatzoptionen:

- `auto_start_zeek=true|false`
- `zeek_log_dir=/pfad/zu/logs`

CLI-Beispiele:

```bash
./bin/tracer -mode run -template examples/tracer-smoke-zeek-lab.json --passive-mode auto --auto-start-zeek true
./bin/tracer -mode run -template examples/tracer-smoke-zeek-lab.json --passive-mode off
./bin/tracer -mode run -template examples/tracer-smoke-zeek-lab.json --passive-mode always --zeek-log-dir /opt/zeek/logs/current
```

## Wohin Es Geht

Die naechsten groesseren Baustellen auf dem Weg zur Vollversion sind:

1. Persistenz ueber mehrere Runs mit Diffs, Verlauf und spaeterem Re-Scheduling
2. Ausbau des Blocking-/Confidence-Modells ueber aktive und passive Evidence
3. weitere passive und Protokoll-Ingests, z. B. `ssl.log`
4. GUI-Schicht fuer Projekte, Runs, Ansichten und Dashboards
5. saubere Import-/Export-Pfade zwischen CLI und GUI

## Ubuntu Tooling

Fuer die Linux-Test-VM gibt es jetzt einen Einzeiler-Installer fuer die benoetigten Werkzeuge:

```bash
bash scripts/install-ubuntu-tools.sh
```

Details und Hinweise stehen in [docs/INSTALL-UBUNTU.md](docs/INSTALL-UBUNTU.md).
