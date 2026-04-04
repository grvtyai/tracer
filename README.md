# tracer

`tracer` wird als orchestrierendes Netzwerk-Scan- und Analyse-System aufgebaut.
Im Kern soll daraus kein loser Wrapper-Stapel werden, sondern eine gemeinsame Laufzeit mit normalisiertem Evidence-Modell, persistenter Historie und spaeter einer GUI fuer Projekte, Dashboards und wiederholbare Scans.

## Vision

Die Zielversion soll sich per Einzeiler auf Ubuntu installieren lassen und danach in zwei Betriebsarten funktionieren:

- als GUI-gestuetztes System fuer Projekte wie `Standort A`, `Heimnetz` oder spaeter reale Kundenstandorte
- als CLI-Variante fuer headless Systeme, die in dasselbe Datenmodell schreibt oder exportierbare Runs fuer die GUI erzeugt

Ein Projekt soll spaeter:

- Scopes, Netze und Profile verwalten
- wiederholbare Scans ausfuehren
- Host- und Service-Inventar aufbauen
- Erreichbarkeit, Blockierung und wahrscheinliche Firewall-Effekte bewerten
- Unterschiede zwischen Runs sichtbar machen
- spaetere Reevals und Dashboards ermoeglichen

## Was Heute Schon Da Ist

Die aktuelle Ausbaustufe lebt vor allem unter `scanner-core/` und bringt bereits einen belastbaren Kern mit:

- modulare Scan-Orchestrierung mit klaren Job-Typen
- aktive Discovery und Verifikation ueber `naabu`, `scamper`, `nmap`, `httpx` und `zgrab2`
- passiver Ingest ueber `Zeek`
- normalisierte JSON-/Evidence-Ausgabe statt tool-spezifischer Rohdaten
- `fail-soft`-Verhalten, damit Teilfehler einzelner Hosts oder Plugins den restlichen Run nicht abbrechen
- Reeval-Hinweise fuer unklare oder spaeter erneut zu pruefende Ergebnisse
- lokale Persistenz ueber `SQLite`
- CLI-Abfragen fuer Projekte, Runs, einzelne Runs und evidence-basierte Diffs

## Aktuelle Features

### Scan-Pipeline

- Scope-Vorbereitung fuer Targets und CIDRs
- optionale L2-Erweiterung mit `arp-scan`, wenn lokal sinnvoll
- Port-Discovery mit `naabu`
- Pfadmessung mit `scamper`
- Service- und OS-Fingerprinting mit `nmap`
- Web-Pruefung mit `httpx`
- Layer-7-Grabs mit `zgrab2`

### Passive Sensorik

- `Zeek` laeuft nicht mehr blind immer mit, sondern ueber `passive_mode`
- `off`, `auto` und `always` sind als gemeinsame Operator-Optionen modelliert
- optionales `auto_start_zeek`
- Zeek-Ingest ist jetzt auf den aktuellen Run-Zeitpunkt und den aktuellen Scope begrenzt
- alte, fachfremde oder ausserhalb des Scopes liegende Logeintraege sollen nicht mehr einfach in aktuelle Runs hineinlaufen

### Resilienz

- Job-Ergebnisse werden pro Schritt gespeichert
- bereits gefundene Evidence bleibt auch bei spaeteren Teilfehlern erhalten
- zweifelhafte Ergebnisse werden als Reeval-Hinweise markiert statt den gesamten Run zu invalidieren
- Blocking-Korrelation beruecksichtigt jetzt bestaetigte aktive Evidence, damit ein Host nicht gleichzeitig praktisch erreichbar und trotzdem pauschal als geblockt gewertet wird

### Persistenz Und Abfragen

- `SQLite` ist das aktuelle Standard-Backend fuer lokale Installationen
- gespeichert werden bereits:
  - Projekte
  - Runs
  - Job-Ergebnisse
  - normalisierte Evidence
  - Blocking-Bewertungen
  - Reeval-Hinweise
- die CLI kann denselben Store lesen:

```bash
./bin/tracer -mode projects
./bin/tracer -mode runs --project "Heimnetz"
./bin/tracer -mode show-run --run-id <run-id>
./bin/tracer -mode diff --baseline-run <run-a> --candidate-run <run-b>
```

Der Default-Store versucht unter `sudo` bewusst den Datenpfad des eigentlichen Operators zu verwenden, statt still nach `/root/.local/share/...` zu schreiben.

## Optionen Als Gemeinsame Grundlage Fuer CLI Und GUI

Ein zentrales Ziel ist, dass spaetere GUI-Optionen nicht separat neu erfunden werden muessen.
Darum laufen typische Operator-Einstellungen bereits heute ueber ein gemeinsames `options`-Modell, das sowohl Templates als auch CLI-Overrides tragen kann.

Beispiele:

- `active_interface`
- `passive_interface`
- `port_template`
- `passive_mode`
- `auto_start_zeek`
- `zeek_log_dir`
- `project`
- `data_dir`
- `db_path`
- `continue_on_error`
- `retain_partial_results`
- `reevaluate_ambiguous`
- `reevaluate_after`

## Roadmap

Die naechsten groesseren Ausbaustufen sind:

1. Dashboard- und GUI-Schicht fuer Projekte, Runs, Filter, Ansichten und spaeter Operator-Workflows
2. weitere Persistenzfunktionen fuer Verlauf, Vergleich und spaeteres Re-Scheduling
3. mehr passive Ingests und Protokolle, z. B. `ssl.log` und weitere Zeek-Quellen
4. bessere Import-/Export-Pfade zwischen CLI, GUI und spaeteren Deployments
5. mehr Scan-Profile, Templates und Operator-Voreinstellungen fuer unterschiedliche Netztypen
6. Installations- und Setup-Pfade fuer eine moeglichst einfache Ubuntu-Vollinstallation

## Ubuntu Tooling

Fuer die Linux-Test-VM gibt es bereits einen Einzeiler-Installer fuer benoetigte Werkzeuge:

```bash
bash scripts/install-ubuntu-tools.sh
```

Mehr dazu steht in [docs/INSTALL-UBUNTU.md](docs/INSTALL-UBUNTU.md).
