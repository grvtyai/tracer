# Package: internal/engine — Plugin Interface

The plugin interface is the extensibility contract for scanner integrations. Each integration implements `engine.Plugin`. The engine dispatches jobs to plugins by calling `CanRun` and then `Run`.

## Plugin Interface

```go
type Plugin interface {
    Name() string
    CanRun(job Job) bool
    Run(ctx context.Context, job Job) ([]evidence.Record, error)
}
```

- `Name()` — unique string identifier, e.g. `"nmap"`. Matches the `source` field on emitted evidence records.
- `CanRun(job)` — returns true if this plugin can handle the given job. Typically checks `job.Kind` and whether required binaries are present.
- `Run(ctx, job)` — executes the scan and returns normalized evidence records. Honors `ctx` cancellation.

## Job

```go
type Job struct {
    ID       string
    RunID    string
    Kind     string            // e.g. "port-scan", "http-probe"
    Target   string
    Port     int
    Protocol string
    Options  map[string]string // plugin-specific config
}
```

## Integrations

Located in `internal/modules/radar/integrations/`. 13 scanner plugins:

| Plugin | Kind(s) | Tool |
|---|---|---|
| nmap | port-scan, service-scan | nmap |
| naabu | port-scan | naabu |
| httpx | http-probe | httpx |
| zgrab2 | banner-grab | zgrab2 |
| testssl | tls-scan | testssl.sh |
| scamper | traceroute | scamper |
| zeek | traffic-analysis | zeek |
| avahi | host-discovery | avahi-browse |
| snmp | snmp-enum | snmpwalk |
| ldap | ldap-enum | ldap tools |
| arp-scan | host-discovery | arp-scan |

## Adding a New Plugin

1. Create a new file in `internal/modules/radar/integrations/`
2. Implement `engine.Plugin`
3. Register the plugin in the integration list that is passed to the engine at startup
4. No API contract change needed — the new plugin name appears automatically in `/capabilities`

## Job Dispatch

The engine iterates the registered plugin list and calls `CanRun(job)` for each job. The first plugin that returns `true` handles the job. Plugins are checked in registration order.

## Error Handling in Plugins

- A plugin returning `error` from `Run` marks the job as `failed`
- Partial results before the error are still returned (slice may be non-empty alongside an error)
- Plugins should use `ctx.Err()` to detect cancellation and return promptly

## Stability

The `Plugin` interface is stable. The evidence record shape is stable. Adding a new plugin requires no changes to the interface or wire contract.
