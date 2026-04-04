# scanner-core

`scanner-core` ist das orchestrierende Herz von `tracer`.
Hier liegen das Scan-Domaenenmodell, die Job-Planung und die Plugin-Vertraege fuer externe Scanner.

## Produktziel

`scanner-core` soll die gemeinsame Laufzeit fuer zwei Betriebsarten werden:

- GUI-gestuetzte Projektinstanzen mit lokaler Persistenz und spaeteren Dashboards
- CLI-Scans auf Systemen ohne GUI, die in dasselbe Modell schreiben oder daraus exportieren

Die Standardpersistenz dafuer ist zunaechst `SQLite`.

## Aktueller Kern

- `arp-scan` fuer L2-Ground-Truth im lokalen Segment
- `naabu` als guenstige Standard-Port-Discovery
- `scamper` fuer selektive Pfadmessung
- `nmap` fuer Service- und OS-Erkennung auf bereits offenen Zielen
- `httpx` fuer Web-Verifikation
- `zgrab2` fuer Layer-7-Grabs
- `zeek` als passiver Ingest-Pfad
- JSON-Normalisierung in ein einheitliches Evidence-Modell

## Resilienz Als Grundlage

- Die Engine ist nicht mehr strikt `fail-fast`, sondern sammelt Job-Ergebnisse pro Schritt.
- Fehlgeschlagene Host-/Plugin-Teile brechen den restlichen Run nicht automatisch ab.
- Bereits gefundene Evidence bleibt fuer weitere Analyse und spaetere Persistenz erhalten.
- Zweifelhafte oder unvollstaendige Ergebnisse koennen als Reeval-Hinweise ausgegeben werden.

## Optionen Fuer CLI Und GUI

- Templates koennen jetzt einen eigenen `options`-Block tragen.
- Diese Optionen werden in effektive Laufzeitoptionen aufgeloest und in den geplanten Jobs mitgefuehrt.
- Dieselbe Struktur ist fuer spaetere GUI-Formulare gedacht und kann heute schon per CLI ueberschrieben werden:
  - `--active-interface`
  - `--passive-interface`
  - `--port-template`
  - `--passive-mode`
  - `--auto-start-zeek`
  - `--zeek-log-dir`
  - `--project`
  - `--data-dir`
  - `--db-path`
  - `--continue-on-error`
  - `--retain-partial-results`
  - `--reevaluate-ambiguous`
  - `--reevaluate-after`

## Zeek-Verhalten

`Zeek` wird jetzt als Bedarfssensor behandelt:

- `off`: kein passiver Pfad
- `auto`: nur einplanen/nutzen, wenn passive Nutzung sinnvoll konfiguriert ist; fehlende Logs stoppen den Run nicht
- `always`: Zeek explizit erwarten und Fehler offen melden

Wenn `auto_start_zeek=true` gesetzt ist, darf der Zeek-Pfad bei Bedarf `zeekctl deploy` versuchen, bevor er auf vorhandene Logs faellt.
Der Ingest wird ausserdem auf den aktuellen Run und den aktuellen Scope begrenzt, damit alte oder fachfremde Logeintraege nicht in einen neuen Scan hineingezogen werden.

## Persistenz

- `SQLite` ist jetzt das vorgesehene Standard-Backend fuer lokale Installationen.
- Gespeichert werden sollen schrittweise:
  - Projekte
  - Runs
  - Job-Ergebnisse
  - normalisierte Evidence
  - Blocking-Bewertungen
  - Reeval-Hinweise
- Das Modell ist darauf ausgelegt, spaeter von GUI und CLI gemeinsam genutzt zu werden.
- Unter `sudo` versucht der Default-Store jetzt, den Datenpfad des eigentlichen Operators zu verwenden. Wer es exakt steuern will, nutzt `--data-dir` oder `--db-path`.

## Abfragen Und Diffs

Die CLI kann jetzt auf derselben SQLite-Datei lesen:

- `-mode projects` listet bekannte Projekte
- `-mode runs --project "Standort A"` listet Runs optional gefiltert nach Projekt
- `-mode show-run --run-id <id>` laedt einen vollstaendigen Run mit Plan, Job-Ergebnissen, Evidence, Blocking und Reeval-Hinweisen
- `-mode diff --baseline-run <id> --candidate-run <id>` vergleicht zwei Runs evidence-basiert

Der aktuelle Diff ist bewusst semantisch und dashboardfreundlich:

- neue Evidence
- verschwundene Evidence
- geaenderte Evidence mit Baseline/Kandidat nebeneinander

## Blocking Und Confidence

- Ziel- und Port-Erreichbarkeit werden aus normalisierter Evidence korreliert.
- Route-basierte Unsicherheit darf bestaetigte aktive Erreichbarkeit nicht mehr schlicht ueberschreiben.
- `probable` und Reeval-Hinweise bleiben erhalten, wenn Datenlage unsicher ist.

## Warum so starten?

Der teuerste Fehler waere, alle Werkzeuge sofort miteinander zu verheiraten und danach festzustellen, dass Ergebnisse nicht sauber korreliert werden koennen.
Dieses Geruest priorisiert deshalb:

1. gemeinsames Scope-Modell
2. explizite Pipeline-Jobs
3. normalisierte Evidence
4. spaeter austauschbare Tool-Runner

## Was als Naechstes kommt

1. Dashboard- und GUI-Schicht auf Basis desselben Persistenzmodells
2. weitere SQLite-basierte Verlaufsauswertung, Vergleichslogik und spaeteres Re-Scheduling
3. Erweiterung des Zeek-Ingests um weitere Logs wie `ssl.log`
4. Ausbau der Operator-Optionen zu vollstaendigen CLI-/GUI-Profilen
5. mehr Scan-Templates und Profile fuer Heimnetz-, Lab- und spaetere Standort-Scans
