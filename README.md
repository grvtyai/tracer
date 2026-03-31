# tracer

`tracer` wird als orchestrierendes Scan-Framework aufgebaut, nicht als Sammlung lose verklebter Wrapper.
Das Ziel ist ein normalisiertes JSON/Evidence-Modell ueber mehreren Discovery-, Routing-, Fingerprint- und AD-Audit-Werkzeugen.

## Startpunkt

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

## Naechster sinnvoller Schritt

Phase 1 implementiert die echten Runner fuer `arp-scan`, `naabu`, `nmap` und `scamper` auf Basis des jetzt angelegten Kernmodells.

## Ubuntu Tooling

Fuer die Linux-Test-VM gibt es jetzt einen Einzeiler-Installer fuer die benoetigten Werkzeuge:

```bash
bash scripts/install-ubuntu-tools.sh
```

Details und Hinweise stehen in [docs/INSTALL-UBUNTU.md](C:\Users\andre\Desktop\repos\tracer\tracer\docs\INSTALL-UBUNTU.md).
