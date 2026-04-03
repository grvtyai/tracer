# scanner-core

`scanner-core` ist das orchestrierende Herz von `tracer`.
Hier liegen das Scan-Domaenenmodell, die Job-Planung und die Plugin-Vertraege fuer externe Scanner.

## Produktziel

`scanner-core` soll die gemeinsame Laufzeit fuer zwei Betriebsarten werden:

- GUI-gestuetzte Projektinstanzen mit lokaler Persistenz und spaeteren Dashboards
- CLI-Scans auf Systemen ohne GUI, die in dasselbe Modell schreiben oder daraus exportieren

Die Standardpersistenz dafuer ist zunaechst `SQLite`.

## Bisheriger Kern

- `arp-scan` fuer L2-Ground-Truth im lokalen Segment
- `naabu` als guenstige Standard-Port-Discovery
- `scamper` fuer selektive Pfadmessung
- `nmap` fuer Service- und OS-Erkennung auf bereits offenen Zielen
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
  - `--project`
  - `--data-dir`
  - `--db-path`
  - `--continue-on-error`
  - `--retain-partial-results`
  - `--reevaluate-ambiguous`
  - `--reevaluate-after`

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

## Warum so starten?

Der teuerste Fehler waere, alle Werkzeuge sofort miteinander zu verheiraten und danach festzustellen, dass Ergebnisse nicht sauber korreliert werden koennen.
Dieses Geruest priorisiert deshalb:

1. gemeinsames Scope-Modell
2. explizite Pipeline-Jobs
3. normalisierte Evidence
4. spaeter austauschbare Tool-Runner

## Was als Naechstes kommt

1. weitere SQLite-basierte Persistenzfunktionen fuer Verlauf, Diffs und Abfragen
2. Bessere Korrelation aktiver und passiver Evidence im Blocking-/Confidence-Modell
3. Erweiterung des Zeek-Ingests um weitere Logs wie `ssl.log`
4. Ausbau der Operator-Optionen zu vollstaendigen CLI-/GUI-Profilen
