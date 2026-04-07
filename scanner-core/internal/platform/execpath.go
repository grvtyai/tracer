package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ResolveExecutable locates a binary in PATH first and then in a few common
// install locations that are frequently missed when Startrace runs under sudo.
func ResolveExecutable(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("executable name is required")
	}

	if hasPathComponent(trimmed) {
		resolved, err := exec.LookPath(trimmed)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}

	if override := strings.TrimSpace(os.Getenv(executableOverrideEnv(trimmed))); override != "" {
		resolved, err := exec.LookPath(override)
		if err != nil {
			return "", fmt.Errorf("resolve %s override %q: %w", trimmed, override, err)
		}
		return resolved, nil
	}

	if resolved, err := exec.LookPath(trimmed); err == nil {
		return resolved, nil
	}

	for _, candidate := range candidateExecutablePaths(trimmed) {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}

	return "", fmt.Errorf("%s executable file not found in PATH", trimmed)
}

func executableOverrideEnv(name string) string {
	normalized := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(name))
	return "STARTRACE_" + normalized + "_PATH"
}

func hasPathComponent(value string) bool {
	return strings.Contains(value, string(filepath.Separator)) || strings.Contains(value, "/") || filepath.IsAbs(value)
}

func candidateExecutablePaths(name string) []string {
	candidates := make([]string, 0, 16)
	seen := make(map[string]struct{})
	add := func(path string) {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		candidates = append(candidates, trimmed)
	}

	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		add(filepath.Join(home, "go", "bin", name))
	}

	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		add(filepath.Join("/home", sudoUser, "go", "bin", name))
	}

	if runtime.GOOS == "linux" {
		if matches, err := filepath.Glob(filepath.Join("/home", "*", "go", "bin", name)); err == nil {
			for _, match := range matches {
				add(match)
			}
		}
	}

	switch runtime.GOOS {
	case "linux":
		for _, dir := range []string{
			"/usr/local/sbin",
			"/usr/local/bin",
			"/usr/sbin",
			"/usr/bin",
			"/sbin",
			"/bin",
			"/snap/bin",
			"/opt/zeek/bin",
			"/opt/zeek/sbin",
			"/root/go/bin",
		} {
			add(filepath.Join(dir, name))
		}
	case "darwin":
		for _, dir := range []string{
			"/opt/homebrew/bin",
			"/usr/local/bin",
			"/usr/bin",
			"/bin",
		} {
			add(filepath.Join(dir, name))
		}
	}

	return candidates
}
