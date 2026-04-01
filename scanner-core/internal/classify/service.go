package classify

import "sort"

var categoryPriority = []string{
	"directory",
	"database",
	"remote_access",
	"messaging",
	"printing",
	"web",
	"general",
}

var portCategories = map[int]string{
	22:    "remote_access",
	23:    "remote_access",
	25:    "messaging",
	53:    "directory",
	80:    "web",
	81:    "web",
	88:    "directory",
	110:   "messaging",
	111:   "general",
	135:   "directory",
	139:   "directory",
	143:   "messaging",
	389:   "directory",
	443:   "web",
	445:   "directory",
	464:   "directory",
	465:   "messaging",
	587:   "messaging",
	591:   "web",
	631:   "printing",
	636:   "directory",
	993:   "messaging",
	995:   "messaging",
	1433:  "database",
	1521:  "database",
	2049:  "general",
	3268:  "directory",
	3269:  "directory",
	3306:  "database",
	3389:  "remote_access",
	5432:  "database",
	5900:  "remote_access",
	6379:  "database",
	8000:  "web",
	8008:  "web",
	8080:  "web",
	8081:  "web",
	8443:  "web",
	9042:  "database",
	27017: "database",
}

func FromPort(port int) string {
	if category, ok := portCategories[port]; ok {
		return category
	}

	return "general"
}

func FromPorts(ports []int) string {
	classes := AllFromPorts(ports)
	if len(classes) == 0 {
		return ""
	}

	return classes[0]
}

func AllFromPorts(ports []int) []string {
	seen := make(map[string]struct{})
	for _, port := range ports {
		seen[FromPort(port)] = struct{}{}
	}

	classes := make([]string, 0, len(seen))
	for _, category := range categoryPriority {
		if _, ok := seen[category]; ok {
			classes = append(classes, category)
		}
	}

	if len(classes) == 0 {
		return []string{"general"}
	}

	return classes
}

func SortClasses(classes []string) []string {
	order := make(map[string]int, len(categoryPriority))
	for index, category := range categoryPriority {
		order[category] = index
	}

	cloned := append([]string{}, classes...)
	sort.SliceStable(cloned, func(i, j int) bool {
		left, leftOK := order[cloned[i]]
		right, rightOK := order[cloned[j]]

		switch {
		case leftOK && rightOK:
			return left < right
		case leftOK:
			return true
		case rightOK:
			return false
		default:
			return cloned[i] < cloned[j]
		}
	})

	return cloned
}
