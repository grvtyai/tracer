package radar

import (
	"fmt"

	"github.com/grvtyai/startrace/scanner-core/internal/api"
	"github.com/grvtyai/startrace/scanner-core/internal/engine"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/platform"
)

// pluginBinaryMap maps an engine.Plugin.Name() to the external binary the
// plugin shells out to. Plugins not in the map are treated as internal
// (always available, no binary dependency).
var pluginBinaryMap = map[string]string{
	"arp-scan":       "arp-scan",
	"avahi":          "avahi-browse",
	"naabu":          "naabu",
	"nmap":           "nmap",
	"scamper":        "scamper",
	"httpx":          "httpx",
	"testssl":        "testssl.sh",
	"snmpwalk":       "snmpwalk",
	"zgrab2":         "zgrab2",
	"zeek":           "zeek",
	"sharphound":     "SharpHound",
	"ldapdomaindump": "ldapdomaindump",
}

// pluginKindsMap advertises which job kinds a plugin services. Kept in a
// lookup table rather than asking the plugin itself so the wire format stays
// decoupled from the plugin implementation.
var pluginKindsMap = map[string][]string{
	"internal":       {"scope_prepare"},
	"arp-scan":       {"l2_discover"},
	"avahi":          {"local_service_discover"},
	"naabu":          {"port_discover"},
	"nmap":           {"service_probe"},
	"scamper":        {"route_probe"},
	"httpx":          {"web_probe"},
	"testssl":        {"tls_inspect"},
	"snmpwalk":       {"snmp_probe"},
	"zgrab2":         {"grab_probe"},
	"zeek":           {"passive_ingest"},
	"sharphound":     {"analyze"},
	"ldapdomaindump": {"analyze"},
}

func buildPluginInfo(p engine.Plugin) api.Plugin {
	name := p.Name()
	info := api.Plugin{
		Name:  name,
		Kinds: pluginKindsMap[name],
	}

	binary, needsBinary := pluginBinaryMap[name]
	if !needsBinary {
		info.Available = true
		return info
	}

	if _, err := platform.ResolveExecutable(binary); err == nil {
		info.Available = true
		return info
	}

	info.Available = false
	info.Reason = fmt.Sprintf("binary %q not found in PATH", binary)
	return info
}
