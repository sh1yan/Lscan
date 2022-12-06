package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// K8sAttack k8s攻击函数
func K8sAttack(info *lc.HostInfo) {
	port, _ := strconv.Atoi(info.ScanPort)
	switch port {
	case 6443:
		k8s6443(info)
		return
	case 10250:
		k8s10250(info)
		return
	case 2379:
		k8setcd(info)
		return
	default:
		logger.Error(fmt.Sprint("No relevant k8s default port"))
		return
	}

}

// k8s6443 k8s6443端口攻击函数
func k8s6443(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[K8S6443]") {
		get, err := http.Get("https://" + ip + ":" + info.ScanPort + "/api/v1/namespaces/default/pods")

		if err != nil {
			result := fmt.Sprintf("[K8S6443] %s:%d There is no unauthorized access to k8s6443!", ip, port)
			logger.Failed(result)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
			}
		}(get.Body)
		all, err := io.ReadAll(get.Body)
		if err != nil {
			result := fmt.Sprintf("[K8S6443] %s:%d There is no unauthorized access to k8s6443!", ip, port)
			logger.Failed(result)
			return
		}
		if strings.Contains(string(all), "PodList") {
			result := fmt.Sprintf("[K8S6443] https://%s:%d/api/v1/namespaces/default/pods K8s6443 has an unauthorized access vulnerability!", ip, port)
			logger.Success(result)
		}
		result := fmt.Sprintf("[K8S6443] %s:%d There is no unauthorized access to k8s6443!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[K8S6443] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

// k8s10250 k8s10250端口攻击函数
func k8s10250(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[K8S10250]") {
		get, err := http.Get("https://" + ip + ":" + info.ScanPort + "/pods")
		if err != nil {
			result := fmt.Sprintf("[K8S10250] https://%s:%d/pods There is no unauthorized access to k8s10250!", ip, port)
			logger.Failed(result)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
			}
		}(get.Body)
		all, err := io.ReadAll(get.Body)
		if err != nil {
			result := fmt.Sprintf("[K8S10250] %s:%d There is no unauthorized access to k8s10250!", ip, port)
			logger.Failed(result)
			return
		}
		if strings.Contains(string(all), "PodList") {
			result := fmt.Sprintf("[K8S10250] %s:%d K8s10250 has an unauthorized access vulnerability!", ip, port)
			logger.Success(result)
		}
		result := fmt.Sprintf("[K8S10250] %s:%d There is no unauthorized access to k8s10250!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[K8S10250] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

// k8setcd k8setcd端口攻击函数
func k8setcd(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[K8SETCD]") {
		get, err := http.Get("http://" + ip + ":" + info.ScanPort + "/version")
		if err != nil {
			result := fmt.Sprintf("[K8SETCD] %s:%d There is no unauthorized access to k8setcd!", ip, port)
			logger.Failed(result)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
			}
		}(get.Body)
		all, err := io.ReadAll(get.Body)
		if err != nil {
			result := fmt.Sprintf("[K8SETCD] %s:%d There is no unauthorized access to k8setcd!", ip, port)
			logger.Failed(result)
			return
		}
		if strings.Contains(string(all), "etcd") {
			result := fmt.Sprintf("[K8SETCD] http://%s:%d/version k8setcd has an unauthorized access vulnerability!", ip, port)
			logger.Success(result)
		}
		result := fmt.Sprintf("[K8SETCD] %s:%d There is no unauthorized access to k8setcd!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[K8SETCD] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}
