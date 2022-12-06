package components

import (
	"Lscan/common/components/logger"
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// PingSystem 使用系统默认Ping命令模式
func PingSystem(host string) bool {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
			result := fmt.Sprintf("SystemPing：%s - The address is alive", host)
			logger.Verbose(result)
			return true
		}
	case "windows":
		cmd := exec.Command("ping", "-n", "1", "-w", "500", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "TTL=") {
			result := fmt.Sprintf("SystemPing：%s - The address is alive", host)
			logger.Verbose(result)
			return true
		}
	case "darwin":
		cmd := exec.Command("ping", "-c", "1", "-t", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
			result := fmt.Sprintf("SystemPing：%s - The address is alive", host)
			logger.Verbose(result)
			return true
		}
	}
	result := fmt.Sprintf("SystemPing：%s - The address is not alive", host)
	logger.Verbose(result)
	return false
}
