package platform

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func RequireRootOnLinux(appName string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if RunsAsRoot() {
		return nil
	}
	return fmt.Errorf("%s must be started with sudo/root on Linux because scanner and sensor plugins require elevated privileges", appName)
}

func RunsAsRoot() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	output, err := exec.Command("id", "-u").Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "0"
}
