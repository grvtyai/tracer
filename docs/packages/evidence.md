# Package: internal/evidence

Canonical evidence model. All scanner plugins emit `evidence.Record` values. This is the normalized, cross-scanner data shape used throughout the system.

## Record

```go
type Record struct {
    ID         string            `json:"id"`
    RunID      string            `json:"run_id"`
    Source     string            `json:"source"`     // plugin name, e.g. "nmap"
    Kind       string            `json:"kind"`       // evidence category
    Target     string            `json:"target"`     // IP or hostname
    Port       int               `json:"port,omitempty"`
    Protocol   string            `json:"protocol,omitempty"` // "tcp", "udp"
    Summary    string            `json:"summary"`    // human-readable one-liner
    RawRef     string            `json:"raw_ref,omitempty"` // path to raw tool output
    Attributes map[string]string `json:"attributes,omitempty"` // plugin-specific KV pairs
    Confidence Confidence        `json:"confidence"`
    ObservedAt time.Time         `json:"observed_at"`
}
```

## Confidence

```go
type Confidence string

const (
    ConfidenceConfirmed  Confidence = "confirmed"   // tool gave a definitive result
    ConfidenceProbable   Confidence = "probable"    // likely but not certain
    ConfidenceAmbiguous  Confidence = "ambiguous"   // unclear, needs corroboration
)
```

## Verdict

Used by the analysis layer (`internal/analysis`), not by plugins directly.

```go
type Verdict string

const (
    VerdictReachable        Verdict = "reachable"
    VerdictConfirmedBlocked Verdict = "confirmed_blocked"
    VerdictProbableBlocked  Verdict = "probable_blocked"
    VerdictAmbiguous        Verdict = "ambiguous"
)
```

## Kind Values (Common)

Kind is a string tag on the record. Common values emitted by the radar integrations:

| Kind | Description |
|---|---|
| `port-open` | A TCP/UDP port was found open |
| `port-closed` | A port was found closed or filtered |
| `http-response` | HTTP probe result (status code, title, tech) |
| `tls-cert` | TLS certificate details |
| `tls-vuln` | TLS vulnerability finding (from testssl) |
| `service-banner` | Raw service banner (from zgrab2) |
| `host-discovered` | Host found reachable (from arp-scan, avahi) |
| `traceroute` | Traceroute path record (from scamper) |
| `traffic-observation` | Passive traffic fact (from zeek) |
| `snmp-value` | SNMP OID value |
| `ldap-entry` | LDAP directory entry |

## Source Values

`Source` matches the plugin `Name()` return value. Examples: `nmap`, `naabu`, `httpx`, `zgrab2`, `testssl`, `scamper`, `zeek`, `avahi`, `snmp`, `ldap`, `arp-scan`.

## Attributes

Plugin-specific key/value pairs. Not normalized across plugins. Examples:

- nmap: `os_guess`, `service_name`, `service_product`, `service_version`
- httpx: `status_code`, `title`, `tech`, `content_length`
- testssl: `finding`, `severity`, `cve`
- tls: `issuer`, `subject`, `san`, `not_before`, `not_after`

## Stability

The `Record` shape is stable. The Plugin interface contract and Evidence storage depend on it. Changes require a migration of the evidence table.
