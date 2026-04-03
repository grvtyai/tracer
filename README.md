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
