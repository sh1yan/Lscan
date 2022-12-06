package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"strconv"
)

func MysqlAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[MYSQL]") {
		for _, user := range lc.UserDict["mysql"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[MYSQL] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res, err := mysqlAuth(ip, info.ScanPort, user, pwd)
				if res == true && err == nil {
					result := fmt.Sprintf("[MYSQL] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[MYSQL] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[MYSQL] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func mysqlAuth(ip string, port string, user string, pass string) (result bool, err error) {
	result = false
	db, err := sql.Open("mysql", user+":"+pass+"@tcp("+ip+":"+port+")/mysql?charset=utf8")
	if err != nil {
	}
	if db.Ping() == nil {
		result = true
	}
	return result, err
}
