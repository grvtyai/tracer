package suite

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/grvtyai/startrace/scanner-core/internal/classify"
	"github.com/grvtyai/startrace/scanner-core/internal/evidence"
	"github.com/grvtyai/startrace/scanner-core/internal/shared/storage"
)

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inventory" {
		http.NotFound(w, r)
		return
	}
	s.renderInventory(w, r, "/inventory")
}

func (s *Server) handleInventoryNetwork(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inventory/network" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}
	projectAssets, err := s.repo.ListAssets(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	runLookup := s.inventoryRunLookup(ctx)
	networkData := buildInventoryNetworkData(*currentProject, projectAssets, runLookup)
	if sats, err := s.repo.ListSatellites(ctx); err == nil {
		for _, sat := range sats {
			networkData.Satellites = append(networkData.Satellites, inventoryNetworkSatNode{
				ID:       sat.ID,
				Name:     sat.Name,
				Address:  sat.Address,
				Status:   sat.Status,
				Platform: sat.Platform,
			})
		}
	}

	data := pageData{
		Title:                "Satelite Network View",
		AppName:              s.options.AppName,
		ActiveNav:            "inventory",
		ActiveSection:        "inventory-network",
		BasePath:             s.options.BasePath,
		DBPath:               s.options.DBPath,
		DataDir:              s.options.DataDir,
		HeroNote:             "Interactive network topology built from the shared inventory",
		Notice:               noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:             projects,
		CurrentProject:       currentProject,
		ProjectSwitchPath:    "/inventory/network",
		Project:              currentProject,
		InventoryNetworkAPI:  buildProjectPath("/api/inventory/network", currentProject),
		InventoryNetworkJSON: marshalTemplateJSON(networkData),
		Settings:             appSettings,
	}
	s.render(w, "inventory_network.html", data)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/assets" {
		http.NotFound(w, r)
		return
	}
	s.renderInventory(w, r, "/assets")
}

func (s *Server) renderInventory(w http.ResponseWriter, r *http.Request, switchPath string) {
	ctx := r.Context()
	projects, currentProject, appSettings, err := s.loadShellContext(ctx, strings.TrimSpace(r.URL.Query().Get("project")))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		http.Redirect(w, r, "/projects/new?notice=create-first-project", http.StatusSeeOther)
		return
	}

	projectAssets, err := s.repo.ListAssets(ctx, currentProject.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	data := pageData{
		Title:             "Inventory",
		AppName:           s.options.AppName,
		ActiveNav:         "inventory",
		ActiveSection:     "inventory-overview",
		BasePath:          s.options.BasePath,
		DBPath:            s.options.DBPath,
		DataDir:           s.options.DataDir,
		HeroNote:          "Shared inventory for every suite module, not only discovery runs",
		Notice:            noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Projects:          projects,
		CurrentProject:    currentProject,
		ProjectSwitchPath: switchPath,
		Project:           currentProject,
		Assets:            projectAssets,
		AssetGroups:       groupAssets(projectAssets),
		InventorySections: buildInventorySections(projectAssets),
		Settings:          appSettings,
	}
	s.render(w, "assets.html", data)
}

func (s *Server) handleInventoryNetworkAPI(w http.ResponseWriter, r *http.Request) {
	projectRef := strings.TrimSpace(r.URL.Query().Get("project"))
	_, currentProject, _, err := s.loadShellContext(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if currentProject == nil {
		s.writeJSON(w, http.StatusOK, inventoryNetworkData{})
		return
	}
	projectRef = currentProject.ID

	projectAssets, err := s.repo.ListAssets(r.Context(), projectRef)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	runLookup := s.inventoryRunLookup(r.Context())
	networkData := buildInventoryNetworkData(*currentProject, projectAssets, runLookup)
	if sats, err := s.repo.ListSatellites(r.Context()); err == nil {
		for _, sat := range sats {
			networkData.Satellites = append(networkData.Satellites, inventoryNetworkSatNode{
				ID:       sat.ID,
				Name:     sat.Name,
				Address:  sat.Address,
				Status:   sat.Status,
				Platform: sat.Platform,
			})
		}
	}
	s.writeJSON(w, http.StatusOK, networkData)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimPrefix(r.URL.Path, "/assets/"), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	assetID := parts[0]
	if len(parts) == 2 && parts[1] == "edit" && r.Method == http.MethodPost {
		s.handleAssetEdit(w, r, assetID)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}

	asset, err := s.repo.GetAsset(r.Context(), assetID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	project, err := s.repo.GetProject(r.Context(), asset.Asset.ProjectID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	projects, _, appSettings, err := s.loadShellContext(r.Context(), project.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	var lastRun *storage.RunDetails
	if strings.TrimSpace(asset.Asset.LastRunID) != "" {
		run, err := s.repo.GetRun(r.Context(), asset.Asset.LastRunID)
		if err == nil {
			lastRun = &run
		}
	}

	data := pageData{
		Title:              "Asset " + asset.Asset.DisplayName,
		AppName:            s.options.AppName,
		ActiveNav:          "inventory",
		ActiveSection:      "inventory-overview",
		BasePath:           s.options.BasePath,
		DBPath:             s.options.DBPath,
		DataDir:            s.options.DataDir,
		Projects:           projects,
		CurrentProject:     &project,
		ProjectSwitchPath:  "/inventory",
		Project:            &project,
		Asset:              &asset,
		AssetReevaluateURL: buildReevaluationURL(project.ID, "Reevaluate "+asset.Asset.DisplayName, asset.Asset.PrimaryTarget, "30m"),
		PortSections:       buildPortSections(asset, lastRun),
		HelpLink:           buildProjectPath("/help/inventory", &project),
		Notice:             noticeMessage(strings.TrimSpace(r.URL.Query().Get("notice"))),
		Settings:           appSettings,
	}
	s.render(w, "asset.html", data)
}

func (s *Server) handleAssetEdit(w http.ResponseWriter, r *http.Request, assetID string) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	asset, err := s.repo.UpdateAsset(r.Context(), assetID, storage.AssetUpdateInput{
		DisplayName:    r.FormValue("display_name"),
		DeviceType:     r.FormValue("manual_device_type"),
		ConnectionType: r.FormValue("manual_connection_type"),
		Reevaluate:     isChecked(r.FormValue("manual_reevaluate")),
		Tags:           splitTags(r.FormValue("tags")),
		Notes:          r.FormValue("manual_notes"),
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.Redirect(w, r, "/assets/"+asset.Asset.ID+"?notice=asset-updated", http.StatusSeeOther)
}

func groupAssets(projectAssets []storage.AssetSummary) []assetGroup {
	grouped := make(map[string][]storage.AssetSummary)
	for _, asset := range projectAssets {
		key := asset.EffectiveDeviceType
		if strings.TrimSpace(key) == "" {
			key = "unknown"
		}
		grouped[key] = append(grouped[key], asset)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	groups := make([]assetGroup, 0, len(keys))
	for _, key := range keys {
		group := assetGroup{Name: key, Assets: grouped[key]}
		sort.Slice(group.Assets, func(i, j int) bool {
			return group.Assets[i].DisplayName < group.Assets[j].DisplayName
		})
		groups = append(groups, group)
	}
	return groups
}

func buildInventorySections(projectAssets []storage.AssetSummary) []inventorySubnetSection {
	type sectionBucket struct {
		id         string
		label      string
		categories map[string]*inventoryCategorySection
	}

	subnet24Counts, subnet16Counts := inventorySubnetCounts(projectAssets)
	sectionBuckets := make(map[string]*sectionBucket)

	for _, asset := range projectAssets {
		sectionID, sectionLabel := inventorySubnetGroup(asset, subnet24Counts, subnet16Counts)
		bucket, ok := sectionBuckets[sectionID]
		if !ok {
			bucket = &sectionBucket{
				id:         sectionID,
				label:      sectionLabel,
				categories: make(map[string]*inventoryCategorySection),
			}
			sectionBuckets[sectionID] = bucket
		}

		categoryKey := normalizedInventoryCategory(asset.EffectiveDeviceType)
		category, ok := bucket.categories[categoryKey]
		if !ok {
			category = &inventoryCategorySection{
				Name:  categoryKey,
				Label: inventoryCategoryLabel(categoryKey),
				Hosts: make([]inventoryHostItem, 0),
			}
			bucket.categories[categoryKey] = category
		}

		servicePreviews, additionalHint := buildInventoryServicePreviews(asset.CurrentOpenPorts)
		category.Hosts = append(category.Hosts, inventoryHostItem{
			ID:                    asset.ID,
			DisplayName:           asset.DisplayName,
			PrimaryTarget:         asset.PrimaryTarget,
			CurrentOS:             asset.CurrentOS,
			DeviceType:            asset.EffectiveDeviceType,
			ConnectionType:        asset.EffectiveConnectionType,
			OpenPortCount:         len(asset.CurrentOpenPorts),
			ServicePreviews:       servicePreviews,
			AdditionalServiceHint: additionalHint,
			DeviceTypeGuess:       asset.DeviceTypeGuess,
			DeviceTypeConfidence:  asset.DeviceTypeConfidence,
			ManualOverride:        strings.TrimSpace(asset.ManualDeviceType) != "",
			Tags:                  asset.Tags,
		})
	}

	keys := make([]string, 0, len(sectionBuckets))
	for key := range sectionBuckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sections := make([]inventorySubnetSection, 0, len(keys))
	for _, key := range keys {
		bucket := sectionBuckets[key]
		categoryKeys := make([]string, 0, len(bucket.categories))
		for categoryKey := range bucket.categories {
			categoryKeys = append(categoryKeys, categoryKey)
		}
		sort.SliceStable(categoryKeys, func(i, j int) bool {
			return inventoryCategorySortWeight(categoryKeys[i]) < inventoryCategorySortWeight(categoryKeys[j])
		})

		section := inventorySubnetSection{
			ID:         bucket.id,
			Label:      bucket.label,
			Categories: make([]inventoryCategorySection, 0, len(categoryKeys)),
		}
		for _, categoryKey := range categoryKeys {
			category := bucket.categories[categoryKey]
			sort.Slice(category.Hosts, func(i, j int) bool {
				if category.Hosts[i].DisplayName == category.Hosts[j].DisplayName {
					return category.Hosts[i].PrimaryTarget < category.Hosts[j].PrimaryTarget
				}
				return category.Hosts[i].DisplayName < category.Hosts[j].DisplayName
			})
			category.HostCount = len(category.Hosts)
			section.HostCount += category.HostCount
			section.Categories = append(section.Categories, *category)
		}
		section.CategoryCount = len(section.Categories)
		sections = append(sections, section)
	}

	if len(sections) == 1 {
		sections[0].ExpandByDefault = true
	}
	return sections
}

func buildInventoryNetworkData(project storage.ProjectSummary, projectAssets []storage.AssetSummary, runLookup func(string) *storage.RunDetails) inventoryNetworkData {
	type pendingHost struct {
		groupID    string
		groupLabel string
		host       inventoryNetworkHost
	}

	hosts := make([]pendingHost, 0, len(projectAssets))
	subnet24Counts, subnet16Counts := inventorySubnetCounts(projectAssets)
	for _, asset := range projectAssets {
		groupID := "inventory_hosts"
		groupLabel := "Inventory Hosts"
		hostID := asset.ID
		hostTarget := firstNonEmptyWeb(asset.PrimaryTarget, asset.DisplayName, asset.ID)
		if addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget); ok {
			hostID = addr.String()
			hostTarget = addr.String()
			groupLabel, groupID = inventoryNetworkLabel(addr, subnet24Counts, subnet16Counts)
		}
		var lastRun *storage.RunDetails
		if runLookup != nil {
			lastRun = runLookup(asset.LastRunID)
		}
		portDetails := buildInventoryPortDetails(asset, lastRun)
		routePath, routeMode, routeSummary := buildInventoryRouteInfo(asset, lastRun)
		graphRole, graphRoleLabel, infrastructure := detectInventoryGraphRole(asset, routePath)

		hosts = append(hosts, pendingHost{
			groupID:    groupID,
			groupLabel: groupLabel,
			host: inventoryNetworkHost{
				ID:               hostID,
				AssetID:          asset.ID,
				DisplayName:      asset.DisplayName,
				Target:           hostTarget,
				DeviceType:       asset.EffectiveDeviceType,
				ConnectionType:   asset.EffectiveConnectionType,
				CurrentOS:        asset.CurrentOS,
				CurrentVendor:    asset.CurrentVendor,
				CurrentProduct:   asset.CurrentProduct,
				OpenPorts:        asset.CurrentOpenPorts,
				PortDetails:      portDetails,
				ObservationCount: asset.ObservationCount,
				Tags:             asset.Tags,
				Status:           inventoryHostStatus(asset),
				RoutePath:        routePath,
				RouteMode:        routeMode,
				RouteSummary:     routeSummary,
				Infrastructure:   infrastructure,
				GraphRole:        graphRole,
				GraphRoleLabel:   graphRoleLabel,
			},
		})
	}

	grouped := make(map[string]*inventoryNetworkGroup)
	for _, item := range hosts {
		groupID := item.groupID
		groupLabel := item.groupLabel

		group, ok := grouped[groupID]
		if !ok {
			group = &inventoryNetworkGroup{ID: groupID, Label: groupLabel, Hosts: make([]inventoryNetworkHost, 0)}
			grouped[groupID] = group
		}
		group.Hosts = append(group.Hosts, item.host)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := inventoryNetworkData{
		RootLabel:    "Origin",
		RootSubLabel: inventoryOriginHostname(),
		Networks:     make([]inventoryNetworkGroup, 0, len(keys)),
	}
	for _, key := range keys {
		group := grouped[key]
		markInventoryGateway(group)
		sort.Slice(group.Hosts, func(i, j int) bool {
			return group.Hosts[i].Target < group.Hosts[j].Target
		})
		group.HostCount = len(group.Hosts)
		out.Networks = append(out.Networks, *group)
	}
	return out
}

func inventorySubnetCounts(projectAssets []storage.AssetSummary) (map[string]int, map[string]int) {
	subnet24Counts := make(map[string]int)
	subnet16Counts := make(map[string]int)
	for _, asset := range projectAssets {
		addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget)
		if !ok {
			continue
		}
		octets := addr.As4()
		group24 := fmt.Sprintf("%d.%d.%d", octets[0], octets[1], octets[2])
		group16 := fmt.Sprintf("%d.%d", octets[0], octets[1])
		subnet24Counts[group24]++
		subnet16Counts[group16]++
	}
	return subnet24Counts, subnet16Counts
}

func parseIPv4AssetTarget(target string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

func inventoryNetworkLabel(addr netip.Addr, subnet24Counts map[string]int, subnet16Counts map[string]int) (string, string) {
	octets := addr.As4()
	key24 := fmt.Sprintf("%d.%d.%d", octets[0], octets[1], octets[2])
	key16 := fmt.Sprintf("%d.%d", octets[0], octets[1])

	if subnet24Counts[key24] > 1 {
		label := fmt.Sprintf("%s.0/24", key24)
		return label, "net_" + strings.ReplaceAll(key24, ".", "_")
	}
	if subnet16Counts[key16] > 1 {
		label := fmt.Sprintf("%s.0.0/16", key16)
		return label, "net_" + strings.ReplaceAll(key16, ".", "_")
	}

	label := addr.String() + "/32"
	return label, "host_" + strings.ReplaceAll(addr.String(), ".", "_")
}

func inventorySubnetGroup(asset storage.AssetSummary, subnet24Counts map[string]int, subnet16Counts map[string]int) (string, string) {
	addr, ok := parseIPv4AssetTarget(asset.PrimaryTarget)
	if !ok {
		return "inventory_hosts", "Inventory Hosts"
	}
	return inventoryNetworkLabel(addr, subnet24Counts, subnet16Counts)
}

func normalizedInventoryCategory(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func inventoryCategoryLabel(value string) string {
	switch normalizedInventoryCategory(value) {
	case "router":
		return "Router"
	case "server":
		return "Server"
	case "workstation":
		return "Workstation"
	case "smartphone":
		return "Smartphone"
	case "tablet":
		return "Tablet"
	case "printer":
		return "Printer"
	case "iot":
		return "IoT"
	default:
		return "Unknown"
	}
}

func inventoryCategorySortWeight(value string) string {
	switch normalizedInventoryCategory(value) {
	case "router":
		return "01_router"
	case "server":
		return "02_server"
	case "workstation":
		return "03_workstation"
	case "smartphone":
		return "04_smartphone"
	case "tablet":
		return "05_tablet"
	case "printer":
		return "06_printer"
	case "iot":
		return "07_iot"
	default:
		return "99_" + normalizedInventoryCategory(value)
	}
}

func buildInventoryServicePreviews(ports []int) ([]inventoryServicePreview, string) {
	if len(ports) == 0 {
		return nil, "No open ports observed."
	}

	cloned := append([]int{}, ports...)
	sort.Ints(cloned)
	limit := len(cloned)
	if limit > 4 {
		limit = 4
	}

	previews := make([]inventoryServicePreview, 0, limit)
	for _, port := range cloned[:limit] {
		previews = append(previews, inventoryServicePreview{
			Port:     port,
			Protocol: "TCP",
			Service:  inventoryServiceName(port),
			Detail:   inventoryServiceDetail(port),
		})
	}

	if len(cloned) > limit {
		return previews, fmt.Sprintf("+%d more ports", len(cloned)-limit)
	}
	return previews, ""
}

func inventoryServiceName(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 110:
		return "POP3"
	case 111:
		return "RPC"
	case 123:
		return "NTP"
	case 135:
		return "RPC Endpoint"
	case 139:
		return "NetBIOS"
	case 143:
		return "IMAP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 465:
		return "SMTPS"
	case 587:
		return "Submission"
	case 631:
		return "IPP"
	case 636:
		return "LDAPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1433:
		return "MSSQL"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP Alt"
	case 8443:
		return "HTTPS Alt"
	default:
		return inventoryServiceClassName(classify.FromPort(port))
	}
}

func inventoryServiceDetail(port int) string {
	switch classify.FromPort(port) {
	case "web":
		return "Webserver"
	case "directory":
		return "Directory Service"
	case "database":
		return "Database Service"
	case "remote_access":
		return "Remote Access"
	case "messaging":
		return "Messaging Service"
	case "printing":
		return "Print Service"
	default:
		return "No more data"
	}
}

func inventoryServiceClassName(category string) string {
	switch strings.TrimSpace(category) {
	case "web":
		return "Web"
	case "directory":
		return "Directory"
	case "database":
		return "Database"
	case "remote_access":
		return "Remote Access"
	case "messaging":
		return "Messaging"
	case "printing":
		return "Printing"
	default:
		return "General Service"
	}
}

func inventoryHostStatus(asset storage.AssetSummary) string {
	switch {
	case len(asset.CurrentOpenPorts) > 0:
		return "online"
	case asset.ObservationCount > 0:
		return "observed"
	default:
		return "unknown"
	}
}

func buildInventoryPortDetails(asset storage.AssetSummary, run *storage.RunDetails) []inventoryPortDetail {
	entries := make(map[int]inventoryPortDetail)

	for _, port := range asset.CurrentOpenPorts {
		entries[port] = inventoryPortDetail{
			Port:     port,
			Protocol: "tcp",
			State:    "OPEN",
			Service:  inventoryServiceName(port),
			Source:   "inventory",
			Detail:   inventoryServiceDetail(port),
			Summary:  "Observed as reachable",
		}
	}

	if run != nil {
		target := strings.TrimSpace(asset.PrimaryTarget)
		for _, record := range run.Evidence {
			if strings.TrimSpace(record.Target) != target || record.Port <= 0 {
				continue
			}
			if !isOpenPortKind(record.Kind) && !strings.EqualFold(record.Kind, "port_state") {
				continue
			}
			detail := describeInventoryPortDetail(record)
			existing, ok := entries[record.Port]
			if !ok || inventoryPortDetailPriority(detail) >= inventoryPortDetailPriority(existing) {
				entries[record.Port] = detail
			}
		}
	}

	ports := make([]int, 0, len(entries))
	for port := range entries {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	out := make([]inventoryPortDetail, 0, len(ports))
	for _, port := range ports {
		out = append(out, entries[port])
	}
	return out
}

func describeInventoryPortDetail(record evidence.Record) inventoryPortDetail {
	protocol := strings.TrimSpace(record.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	state := "OPEN"
	if strings.EqualFold(record.Kind, "port_state") {
		switch strings.ToLower(strings.TrimSpace(record.Attributes["state"])) {
		case "blocked":
			state = "BLOCKED"
		case "filtered":
			state = "FILTERED"
		case "closed":
			state = "CLOSED"
		}
	}

	service := firstNonEmptyWeb(
		record.Attributes["service_name"],
		record.Attributes["web_server"],
		record.Attributes["title"],
		inventoryServiceName(record.Port),
	)
	product := strings.TrimSpace(record.Attributes["product"])
	version := firstNonEmptyWeb(record.Attributes["version"], record.Attributes["tls_version"])
	detail := firstNonEmptyWeb(
		record.Attributes["title"],
		record.Attributes["tech"],
		record.Attributes["extra_info"],
		record.Attributes["content_type"],
		record.Attributes["location"],
		record.Attributes["state_reason"],
		record.Attributes["status"],
		record.Summary,
	)

	return inventoryPortDetail{
		Port:     record.Port,
		Protocol: protocol,
		State:    state,
		Service:  service,
		Product:  product,
		Version:  version,
		Source:   record.Source,
		Summary:  strings.TrimSpace(record.Summary),
		Detail:   detail,
	}
}

func inventoryPortDetailPriority(detail inventoryPortDetail) int {
	score := 0
	if detail.Service != "" {
		score += 4
	}
	if detail.Product != "" {
		score += 3
	}
	if detail.Version != "" {
		score += 2
	}
	if detail.Detail != "" {
		score++
	}
	return score
}

func buildInventoryRouteInfo(asset storage.AssetSummary, run *storage.RunDetails) ([]string, string, string) {
	if run == nil {
		return nil, "", ""
	}
	target := strings.TrimSpace(asset.PrimaryTarget)
	if target == "" {
		return nil, "", ""
	}

	for _, record := range run.Evidence {
		if !strings.EqualFold(record.Kind, "route_trace") || strings.TrimSpace(record.Target) != target {
			continue
		}
		hops := splitCSVList(record.Attributes["hop_addrs"])
		if len(hops) == 0 {
			continue
		}
		if hops[len(hops)-1] != target {
			hops = append(hops, target)
		}
		return hops, "exact", firstNonEmptyWeb(record.Summary, "Route trace available")
	}

	return nil, "", ""
}

func detectInventoryGraphRole(asset storage.AssetSummary, routePath []string) (string, string, bool) {
	joined := strings.ToLower(strings.Join([]string{
		asset.DisplayName,
		asset.PrimaryTarget,
		asset.CurrentHostname,
		asset.CurrentOS,
		asset.CurrentVendor,
		asset.CurrentProduct,
	}, " "))

	hasPort := func(port int) bool {
		return slices.Contains(asset.CurrentOpenPorts, port)
	}

	switch {
	case containsAny(joined, "pfsense", "opnsense", "firewall", "fortigate", "fortinet", "sophos", "checkpoint", "netgate", "utm"):
		return "firewall", "Firewall", true
	case containsAny(joined, "domain controller", "active directory") || ((hasPort(88) || hasPort(389) || hasPort(636) || hasPort(3268)) && (containsAny(joined, "windows server", "microsoft") || hasPort(445))):
		return "domain_controller", "Domain Controller", true
	case normalizedInventoryCategory(asset.EffectiveDeviceType) == "router":
		return "router", "Router", true
	case containsAny(joined, "switch", "catalyst", "aruba", "procurve", "netgear", "unifi switch", "edge switch", "mikrotik switch"):
		return "switch", "Switch", true
	case hasPort(53) && (hasPort(53) || hasPort(853)) && normalizedInventoryCategory(asset.EffectiveDeviceType) != "router":
		return "dns", "DNS Server", true
	case len(routePath) > 1:
		return "gateway", "Gateway", true
	default:
		return "host", inventoryCategoryLabel(asset.EffectiveDeviceType), false
	}
}

func inventoryOriginHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "startrace-host"
	}
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return "startrace-host"
	}
	return trimmed
}

func markInventoryGateway(group *inventoryNetworkGroup) {
	if group == nil || len(group.Hosts) == 0 {
		return
	}

	referencedFirstHops := make(map[string]int)
	for _, host := range group.Hosts {
		if len(host.RoutePath) > 1 {
			referencedFirstHops[host.RoutePath[0]]++
		}
	}

	bestIndex := -1
	bestScore := 0
	for index := range group.Hosts {
		score := inventoryGatewayScore(group.Hosts[index]) + referencedFirstHops[group.Hosts[index].Target]*6
		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}

	if bestIndex < 0 || bestScore < 8 {
		return
	}

	group.GatewayID = group.Hosts[bestIndex].ID
	group.Hosts[bestIndex].IsGateway = true
	group.Hosts[bestIndex].Infrastructure = true
	if strings.TrimSpace(group.Hosts[bestIndex].GraphRole) == "" || group.Hosts[bestIndex].GraphRole == "host" {
		group.Hosts[bestIndex].GraphRole = "gateway"
		group.Hosts[bestIndex].GraphRoleLabel = "Gateway"
	}
	for index := range group.Hosts {
		if index == bestIndex {
			if len(group.Hosts[index].RoutePath) == 0 {
				group.Hosts[index].RoutePath = []string{group.Hosts[index].Target}
				group.Hosts[index].RouteMode = "inferred"
				group.Hosts[index].RouteSummary = "Gateway candidate for this subnet"
			}
			continue
		}
		if len(group.Hosts[index].RoutePath) == 0 {
			group.Hosts[index].RoutePath = []string{group.Hosts[bestIndex].Target, group.Hosts[index].Target}
			group.Hosts[index].RouteMode = "inferred"
			group.Hosts[index].RouteSummary = "Inferred path through subnet gateway"
		}
	}
}

func inventoryGatewayScore(host inventoryNetworkHost) int {
	score := 0
	if host.Infrastructure {
		score += 4
	}
	switch normalizedInventoryCategory(host.DeviceType) {
	case "router":
		score += 14
	case "server":
		score += 5
	}
	if strings.Contains(strings.ToLower(host.CurrentProduct), "firewall") || strings.Contains(strings.ToLower(host.CurrentProduct), "gateway") {
		score += 7
	}
	if strings.Contains(strings.ToLower(host.CurrentVendor), "pfsense") || strings.Contains(strings.ToLower(host.CurrentVendor), "opnsense") {
		score += 6
	}
	if hostHasPort(host, 53) {
		score += 3
	}
	if hostHasPort(host, 67) || hostHasPort(host, 68) {
		score += 4
	}
	if hostHasPort(host, 80) || hostHasPort(host, 443) {
		score += 1
	}
	if len(host.RoutePath) > 0 {
		score += 2
	}
	return score
}

func hostHasPort(host inventoryNetworkHost, port int) bool {
	for _, current := range host.OpenPorts {
		if current == port {
			return true
		}
	}
	return false
}

func splitCSVList(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func containsAny(joined string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(joined, strings.ToLower(strings.TrimSpace(needle))) {
			return true
		}
	}
	return false
}

func splitTags(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	})
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	return tags
}
