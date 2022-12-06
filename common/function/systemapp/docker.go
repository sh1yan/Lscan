package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// DockerAttack Docker攻击函数
func DockerAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[DOCKER]") {
		get, err := http.Get("http://" + ip + ":" + info.ScanPort + "/version")
		if err != nil {
			result := fmt.Sprintf("[DOCKER] %s:%d There is no unauthorized access to docker!", ip, port)
			logger.Failed(result)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
			}
		}(get.Body)
		all, err := ioutil.ReadAll(get.Body)
		if err != nil {
			result := fmt.Sprintf("[DOCKER] %s:%d There is no unauthorized access to docker!", ip, port)
			logger.Failed(result)
			return
		}
		if strings.Contains(string(all), "Version") && strings.Contains(string(all), "Arch") && strings.Contains(string(all), "Os") {
			result := fmt.Sprintf("[DOCKER] %s:%d Docker has an unauthorized access vulnerability!", ip, port)
			logger.Success(result)
		}

		result := fmt.Sprintf("[DOCKER] %s:%d There is no unauthorized access to docker!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[DOCKER] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}
