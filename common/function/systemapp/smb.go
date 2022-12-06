package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"github.com/stacktitan/smb/smb"
	"strconv"
)

// SmbAttack SMB口令爆破函数
func SmbAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[SMB]") {
		for _, user := range lc.UserDict["smb"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[SMB] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res, err := smbAuth(ip, port, user, pwd)
				if res == true && err == nil {
					result := fmt.Sprintf("[SMB] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[SMB] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[SMB] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

// Not Support 2003
func smbAuth(ip string, port int, username string, password string) (result bool, err error) {
	result = false

	options := smb.Options{
		Host:        ip,
		Port:        port,
		User:        username,
		Password:    password,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			result = true
		}
	}
	return result, err
}
