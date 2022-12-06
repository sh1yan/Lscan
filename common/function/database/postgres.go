package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"database/sql"
	"fmt"
	"strconv"
	"time"
)

var Timeout time.Duration

func PostgresAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[POSTGRES]") {
		for _, user := range lc.UserDict["postgres"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[POSTGRES] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res := postgresAuth(ip, user, pwd, port)
				if res == true {
					result := fmt.Sprintf("[POSTGRES] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[POSTGRES] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[POSTGRES] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func postgresAuth(ip, user, pwd string, port int) (result bool) {
	DSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d", user, pwd, ip, port, Timeout)
	db, err := sql.Open("postgres", DSN)
	if err == nil {
		err = db.Ping()
		if err == nil {
			return true
		}

		db.Close()
	}
	return false
}
