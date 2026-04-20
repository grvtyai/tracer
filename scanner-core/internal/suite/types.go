package suite

import (
	"html/template"
	"time"

	"github.com/grvtyai/startrace/scanner-core/internal/options"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

type pageData struct {
	Title                 string
	AppName               string
	BrandLogoURL          string
	ActiveNav             string
	ActiveSection         string
	SuiteModules          []suiteModule
	ModuleNav             []moduleNavItem
	BasePath              string
	DBPath                string
	DataDir               string
	BodyClass             string
	HeroNote              string
	Notice                string
	Project               *storage.ProjectSummary
	Projects              []storage.ProjectSummary
	CurrentProject        *storage.ProjectSummary
	ProjectSwitchPath     string
	ProjectForm           projectFormData
	Settings              storage.AppSettings
	PreflightChecks       []preflightCheck
	PreflightGroups       []preflightGroup
	PreflightHealthy      bool
	PreflightState        string
	ScanForm              scanFormData
	RecentRuns            []storage.RunSummary
	CompareBaselineRunID  string
	CompareCandidateRunID string
	RecentRunItems        []runListItem
	Runs                  []storage.RunSummary
	RunItems              []runListItem
	Run                   *storage.RunDetails
	RunReevaluateURL      string
	Assets                []storage.AssetSummary
	Asset                 *storage.AssetDetails
	AssetReevaluateURL    string
	PortSections          []portSection
	AssetGroups           []assetGroup
	InventorySections     []inventorySubnetSection
	Hosts                 []hostSummary
	RunStatus             statusInfo
	ScheduledScans        []storage.ScheduledScan
	WarningDetails        []warningDetail
	HelpLink              string
	Stats                 dashboardStats
	DashboardCharts       []dashboardChart
	InventoryNetworkAPI   string
	InventoryNetworkJSON  template.JS
	DiscoveryTemplates    []discoveryTemplateCard
	HelpTopics            []helpTopicCard
	HelpLatest            []helpTopicCard
	HelpTopic             *helpTopicPage
	HelpSearchQuery       string
	RepoURL               string
	RepoPath              string
	DefaultProjectLabel   string
	DefaultSatelliteLabel string
	DeviceTypeStats       []labelCount
	ConnectionStats       []labelCount
	StatusStats           []labelCount
	SuiteCards            []suiteCard
	OverviewText          string
	CurrentStateItems     []string
	RoadmapItems          []string
	PrimaryAction         *pageAction
	SecondaryAction       *pageAction
	ModuleImageURL        string
	DiffAPI               string
	SatelliteOptions      []satelliteOption
	MonitoringSatellites  []monitoringSatellite
	MonitoringJobs        []monitoringJob
	MonitoringNexus       *monitoringSatellite
	MonitoringStats       []monitoringStat
	MonitoringFacts       []monitoringFact
	MonitoringTooling     []monitoringTool
	MonitoringChecks      []monitoringCheck
	RunExecutionFacts     []monitoringFact
	RunJobItems           []runJobItem
	MonitoringJobQuery    string
	MonitoringJobStatus   string
	SatelliteRegisterForm satelliteRegisterFormData
}

type satelliteOption struct {
	ID     string
	Label  string
	Detail string
}

type monitoringSatellite struct {
	ID          string
	Name        string
	Role        string
	Status      string
	StatusClass string
	Address     string
	Hostname    string
	Platform    string
	Executor    string
	LastSeen    string
	FirstSeen   string
	Summary     string
}

type monitoringJob struct {
	ID          string
	URL         string
	Name        string
	Project     string
	Target      string
	Execution   string
	Status      string
	StatusClass string
	StartedAt   string
	FinishedAt  string
	JobCount    int
	Evidence    int
	Running     bool
	Summary     string
}

type monitoringStat struct {
	Label       string
	Value       string
	Detail      string
	StatusClass string
}

type monitoringFact struct {
	Key   string
	Value string
}

type monitoringTool struct {
	Name        string
	Required    bool
	Status      string
	StatusClass string
	Path        string
	Version     string
	Runtime     string
}

type monitoringCheck struct {
	Name        string
	Status      string
	StatusClass string
	Detail      string
}

type runJobItem struct {
	ID                 string
	Kind               string
	Plugin             string
	Target             string
	Status             string
	StatusClass        string
	StartedAt          string
	FinishedAt         string
	Duration           string
	RecordsWritten     int
	Error              string
	NeedsReevaluation  bool
	ReevaluationAfter  string
	ReevaluationReason string
}

type satelliteRegisterFormData struct {
	Name              string
	Address           string
	Role              string
	RegistrationToken string
}

type dashboardStats struct {
	RunCount       int
	AssetCount     int
	HostCount      int
	EvidenceCount  int
	ReevalCount    int
	SatelliteCount int
	SubnetCount    int
	OpenPortCount  int
	CVECount       int
	CriticalCVEs   int
}

type hostSummary struct {
	AssetID         string
	Target          string
	Verdict         string
	Confidence      string
	OpenPorts       []int
	EvidenceCount   int
	BlockingReasons []string
	LastObserved    time.Time
	Reevaluate      bool
}

type assetGroup struct {
	Name   string
	Assets []storage.AssetSummary
}

type inventorySubnetSection struct {
	ID              string
	Label           string
	HostCount       int
	CategoryCount   int
	Categories      []inventoryCategorySection
	ExpandByDefault bool
}

type inventoryCategorySection struct {
	Name      string
	Label     string
	HostCount int
	Hosts     []inventoryHostItem
}

type inventoryHostItem struct {
	ID                    string
	DisplayName           string
	PrimaryTarget         string
	CurrentOS             string
	DeviceType            string
	ConnectionType        string
	OpenPortCount         int
	ServicePreviews       []inventoryServicePreview
	AdditionalServiceHint string
	DeviceTypeGuess       string
	DeviceTypeConfidence  string
	ManualOverride        bool
	Tags                  []string
}

type inventoryServicePreview struct {
	Port     int
	Protocol string
	Service  string
	Detail   string
}

type portSection struct {
	Title        string
	Class        string
	DefaultOpen  bool
	Entries      []portEntry
	Summary      string
	EmptyMessage string
}

type portEntry struct {
	Port    int
	Label   string
	Detail  string
	Summary string
}

type labelCount struct {
	Label string
	Count int
}

type dashboardChart struct {
	Title        string
	TotalValue   int
	Segments     []dashboardChartSegment
	EmptyMessage string
}

type dashboardChartSegment struct {
	Label        string
	Count        int
	PercentLabel string
	Color        string
	DashArray    string
	DashOffset   string
	Tooltip      string
}

type inventoryNetworkData struct {
	RootLabel    string                    `json:"root_label"`
	RootSubLabel string                    `json:"root_sub_label,omitempty"`
	Networks     []inventoryNetworkGroup   `json:"networks"`
	Satellites   []inventoryNetworkSatNode `json:"satellites,omitempty"`
}

type inventoryNetworkSatNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address,omitempty"`
	Status   string `json:"status"`
	Platform string `json:"platform,omitempty"`
}

type inventoryNetworkGroup struct {
	ID        string                 `json:"id"`
	Label     string                 `json:"label"`
	HostCount int                    `json:"host_count"`
	GatewayID string                 `json:"gateway_id,omitempty"`
	Hosts     []inventoryNetworkHost `json:"hosts"`
}

type inventoryNetworkHost struct {
	ID               string                `json:"id"`
	AssetID          string                `json:"asset_id"`
	DisplayName      string                `json:"display_name"`
	Target           string                `json:"target"`
	DeviceType       string                `json:"device_type"`
	ConnectionType   string                `json:"connection_type"`
	CurrentOS        string                `json:"current_os,omitempty"`
	CurrentVendor    string                `json:"current_vendor,omitempty"`
	CurrentProduct   string                `json:"current_product,omitempty"`
	OpenPorts        []int                 `json:"open_ports,omitempty"`
	PortDetails      []inventoryPortDetail `json:"port_details,omitempty"`
	ObservationCount int                   `json:"observation_count"`
	Tags             []string              `json:"tags,omitempty"`
	Status           string                `json:"status"`
	RoutePath        []string              `json:"route_path,omitempty"`
	RouteMode        string                `json:"route_mode,omitempty"`
	RouteSummary     string                `json:"route_summary,omitempty"`
	IsGateway        bool                  `json:"is_gateway,omitempty"`
	Infrastructure   bool                  `json:"infrastructure,omitempty"`
	GraphRole        string                `json:"graph_role,omitempty"`
	GraphRoleLabel   string                `json:"graph_role_label,omitempty"`
}

type inventoryPortDetail struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source,omitempty"`
	Summary  string `json:"summary,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type statusInfo struct {
	Label   string
	Class   string
	Title   string
	Message string
}

type warningDetail struct {
	Plugin string
	Host   string
	JobID  string
	Error  string
	Kind   string
}

type runListItem struct {
	Run          storage.RunSummary `json:"run"`
	HostCount    int                `json:"host_count"`
	SubnetCount  int                `json:"subnet_count"`
	StatusLabel  string             `json:"status_label"`
	StatusClass  string             `json:"status_class"`
	ScanTag      string             `json:"scan_tag"`
	ScanTagClass string             `json:"scan_tag_class"`
	Clickable    bool               `json:"clickable"`
}

type projectFormData struct {
	Name            string
	Notes           string
	StoragePath     string
	TargetDBPath    string
	OwnerUsername   string
	PublicIDPreview string
	TargetDBExists  bool
}

type optionsResponse struct {
	AppName      string                   `json:"app_name"`
	DBPath       string                   `json:"db_path"`
	DataDir      string                   `json:"data_dir"`
	PassiveModes []string                 `json:"passive_modes"`
	Defaults     options.EffectiveOptions `json:"defaults"`
}
