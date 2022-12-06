package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"database/sql"
	"fmt"
	"strconv"
)

// MssqlAttack MSSQL口令爆破函数
func MssqlAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[MSSQL]") {
		for _, user := range lc.UserDict["mssql"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[MSSQL] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res, err := mssqlAuth(ip, info.ScanPort, user, pwd)
				if res == true && err == nil {
					result := fmt.Sprintf("[MSSQL] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[MSSQL] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[MSSQL] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func mssqlAuth(ip, port, user, pass string) (result bool, err error) {
	result = false
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%s;encrypt=disable", ip, user, pass, port)
	db, err := sql.Open("mssql", connString)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result = true
		}
	}

	return result, err
}
