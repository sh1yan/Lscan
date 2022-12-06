package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"database/sql"
	"fmt"
	"strconv"
)

// OracleAttack ORACLE口令爆破函数
func OracleAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[ORACLE]") {
		for _, user := range lc.UserDict["oracle"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[ORACLE] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				ok := oracleAuth(ip, info.ScanPort, user, pwd)
				if ok {
					result := fmt.Sprintf("[ORACLE] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[ORACLE] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[ORACLE] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func oracleAuth(host, port, user, pass string) bool {
	db, err := sql.Open("godror", user+"/"+pass+"@"+host+":"+port+"/orcl")
	if err == nil {
		//defer db.Close()
		err = db.Ping()
		if err == nil {
			return true
		}
	}

	return false
}
