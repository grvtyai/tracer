package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/grvtyai/tracer/scanner-core/internal/engine"
	"github.com/grvtyai/tracer/scanner-core/internal/evidence"
	"github.com/grvtyai/tracer/scanner-core/internal/jobs"
)

type Runner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type Plugin struct {
	binary string
	runner Runner
	now    func() time.Time
}

var _ engine.Plugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{
		binary: "nmap",
		runner: ExecRunner{},
		now:    time.Now,
	}
}

func (p *Plugin) Name() string {
	return "nmap"
}

func (p *Plugin) CanRun(job jobs.Job) bool {
	return job.Kind == jobs.KindServiceProbe
}

func (p *Plugin) Run(ctx context.Context, job jobs.Job) ([]evidence.Record, error) {
	if len(job.Targets) == 0 {
		return nil, errors.New("nmap requires at least one target")
	}

	runner := p.runner
	if runner == nil {
		runner = ExecRunner{}
	}

	binary := p.binary
	if binary == "" {
		binary = "nmap"
	}

	output, err := runner.Run(ctx, binary, BuildArgs(job))
	if err != nil {
		if len(output) == 0 {
			return nil, fmt.Errorf("run nmap: %w", err)
		}
		return nil, fmt.Errorf("run nmap: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return ParseOutput(output, job, p.timeNow())
}

func (p *Plugin) timeNow() time.Time {
	if p.now != nil {
		return p.now().UTC()
	}

	return time.Now().UTC()
}

func BuildArgs(job jobs.Job) []string {
	args := []string{"-oX", "-", "-Pn", "-sV"}

	if includeOSDetection(job) {
		args = append(args, "-O")
	}

	if serviceVersionIntensity := strings.TrimSpace(job.Metadata["version_intensity"]); serviceVersionIntensity != "" {
		args = append(args, "--version-intensity", serviceVersionIntensity)
	}

	if timing := strings.TrimSpace(job.Metadata["timing_template"]); timing != "" {
		args = append(args, timingFlag(timing))
	}

	if ports := joinPorts(job.Ports); ports != "" {
		args = append(args, "-p", ports)
	}

	args = append(args, job.Targets...)
	return args
}

func ParseOutput(output []byte, job jobs.Job, observedAt time.Time) ([]evidence.Record, error) {
	var report run
	if err := xml.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("decode nmap xml: %w", err)
	}

	records := make([]evidence.Record, 0)
	for _, host := range report.Hosts {
		target := host.primaryTarget()
		if target == "" {
			continue
		}

		for _, port := range host.Ports {
			if strings.ToLower(port.State.State) != "open" {
				continue
			}

			records = append(records, buildServiceRecord(target, host.primaryHostname(), port, job, observedAt))
		}

		if osRecord, ok := buildOSRecord(target, host.primaryHostname(), host.OS, job, observedAt); ok {
			records = append(records, osRecord)
		}
	}

	return records, nil
}

func buildServiceRecord(target, hostname string, port port, job jobs.Job, observedAt time.Time) evidence.Record {
	summary := fmt.Sprintf(
		"service fingerprint for %s/%d on %s",
		port.Protocol,
		port.PortID,
		target,
	)
	if serviceName := strings.TrimSpace(port.Service.Name); serviceName != "" {
		summary = fmt.Sprintf(
			"%s detected on %s/%d at %s",
			serviceName,
			port.Protocol,
			port.PortID,
			target,
		)
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:%s:%d:service", job.ID, target, port.Protocol, port.PortID),
		RunID:      job.Metadata["run_id"],
		Source:     "nmap",
		Kind:       "service_fingerprint",
		Target:     target,
		Port:       port.PortID,
		Protocol:   normalizeProtocol(port.Protocol),
		Summary:    summary,
		RawRef:     fmt.Sprintf("xml:host:%s:port:%d", target, port.PortID),
		Attributes: buildServiceAttributes(hostname, port, job),
		Confidence: evidence.ConfidenceConfirmed,
		ObservedAt: observedAt,
	}
}

func buildOSRecord(target, hostname string, osInfo osBlock, job jobs.Job, observedAt time.Time) (evidence.Record, bool) {
	if len(osInfo.Matches) == 0 {
		return evidence.Record{}, false
	}

	best := osInfo.Matches[0]
	attributes := map[string]string{
		"job_id":       job.ID,
		"plugin":       "nmap",
		"job_kind":     string(job.Kind),
		"os_name":      best.Name,
		"os_accuracy":  best.Accuracy,
		"match_count":  strconv.Itoa(len(osInfo.Matches)),
		"service_scan": "true",
	}

	if hostname != "" {
		attributes["hostname"] = hostname
	}

	if len(best.Classes) > 0 {
		class := best.Classes[0]
		if class.Family != "" {
			attributes["os_family"] = class.Family
		}
		if class.Generation != "" {
			attributes["os_generation"] = class.Generation
		}
		if class.Type != "" {
			attributes["os_type"] = class.Type
		}
		if class.Vendor != "" {
			attributes["vendor"] = class.Vendor
		}
	}

	return evidence.Record{
		ID:         fmt.Sprintf("%s:%s:os", job.ID, target),
		RunID:      job.Metadata["run_id"],
		Source:     "nmap",
		Kind:       "host_os_fingerprint",
		Target:     target,
		Protocol:   "ip",
		Summary:    fmt.Sprintf("OS fingerprint for %s suggests %s", target, best.Name),
		RawRef:     fmt.Sprintf("xml:host:%s:os", target),
		Attributes: attributes,
		Confidence: confidenceFromAccuracy(best.Accuracy),
		ObservedAt: observedAt,
	}, true
}

func buildServiceAttributes(hostname string, port port, job jobs.Job) map[string]string {
	attributes := map[string]string{
		"job_id":         job.ID,
		"plugin":         "nmap",
		"job_kind":       string(job.Kind),
		"state":          port.State.State,
		"state_reason":   port.State.Reason,
		"service_name":   port.Service.Name,
		"service_method": port.Service.Method,
		"service_conf":   port.Service.Conf,
	}

	if hostname != "" {
		attributes["hostname"] = hostname
	}
	if product := strings.TrimSpace(port.Service.Product); product != "" {
		attributes["product"] = product
	}
	if version := strings.TrimSpace(port.Service.Version); version != "" {
		attributes["version"] = version
	}
	if extraInfo := strings.TrimSpace(port.Service.ExtraInfo); extraInfo != "" {
		attributes["extra_info"] = extraInfo
	}
	if tunnel := strings.TrimSpace(port.Service.Tunnel); tunnel != "" {
		attributes["tunnel"] = tunnel
	}
	if osType := strings.TrimSpace(port.Service.OSType); osType != "" {
		attributes["os_type"] = osType
	}
	if deviceType := strings.TrimSpace(port.Service.DeviceType); deviceType != "" {
		attributes["device_type"] = deviceType
	}
	if serviceClass := strings.TrimSpace(job.ServiceClass); serviceClass != "" {
		attributes["service_class"] = serviceClass
	}

	return attributes
}

func confidenceFromAccuracy(accuracy string) evidence.Confidence {
	value, err := strconv.Atoi(strings.TrimSpace(accuracy))
	if err != nil {
		return evidence.ConfidenceProbable
	}

	switch {
	case value >= 95:
		return evidence.ConfidenceConfirmed
	case value >= 80:
		return evidence.ConfidenceProbable
	default:
		return evidence.ConfidenceAmbiguous
	}
}

func includeOSDetection(job jobs.Job) bool {
	value, ok := job.Metadata["os_detection"]
	if !ok {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func timingFlag(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "-T3"
	}

	if strings.HasPrefix(normalized, "-T") {
		return normalized
	}

	return "-T" + normalized
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}

	return strings.Join(values, ",")
}

func normalizeProtocol(protocol string) string {
	value := strings.ToLower(strings.TrimSpace(protocol))
	if value == "" {
		return "tcp"
	}

	return value
}

type run struct {
	Hosts []host `xml:"host"`
}

type host struct {
	Addresses []address `xml:"address"`
	Hostnames hostnames `xml:"hostnames"`
	Ports     []port    `xml:"ports>port"`
	OS        osBlock   `xml:"os"`
}

func (h host) primaryTarget() string {
	for _, address := range h.Addresses {
		if address.Type == "ipv4" || address.Type == "ipv6" {
			return strings.TrimSpace(address.Addr)
		}
	}

	for _, address := range h.Addresses {
		if strings.TrimSpace(address.Addr) != "" {
			return strings.TrimSpace(address.Addr)
		}
	}

	return ""
}

func (h host) primaryHostname() string {
	if len(h.Hostnames.Items) == 0 {
		return ""
	}

	return strings.TrimSpace(h.Hostnames.Items[0].Name)
}

type address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type hostnames struct {
	Items []hostname `xml:"hostname"`
}

type hostname struct {
	Name string `xml:"name,attr"`
}

type port struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    portState `xml:"state"`
	Service  service   `xml:"service"`
}

type portState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type service struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Tunnel     string `xml:"tunnel,attr"`
	Method     string `xml:"method,attr"`
	Conf       string `xml:"conf,attr"`
	OSType     string `xml:"ostype,attr"`
	DeviceType string `xml:"devicetype,attr"`
}

type osBlock struct {
	Matches []osMatch `xml:"osmatch"`
}

type osMatch struct {
	Name     string    `xml:"name,attr"`
	Accuracy string    `xml:"accuracy,attr"`
	Classes  []osClass `xml:"osclass"`
}

type osClass struct {
	Type       string `xml:"type,attr"`
	Vendor     string `xml:"vendor,attr"`
	Family     string `xml:"osfamily,attr"`
	Generation string `xml:"osgen,attr"`
	Accuracy   string `xml:"accuracy,attr"`
}
