package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	mgo "gopkg.in/mgo.v2"
	"strconv"
	"time"
)

func MongodbAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[MONGODB]") {
		res1, _ := mongoNullAuth(ip, info.ScanPort)
		if res1 {
			result := fmt.Sprintf("[MONGODB] %s:%d Anonymous login succeeded! ", ip, port)
			logger.Success(result)
			return
		}
		for _, user := range lc.UserDict["mongodb"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprint("[MONGODB] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res, err := mongoAuth(ip, info.ScanPort, user, pwd)
				if res == true && err == nil {
					result := fmt.Sprintf("[MONGODB] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[MONGODB] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[MONGODB] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func mongoAuth(ip, port, username, password string) (result bool, err error) {
	result = false
	session, err := mgo.DialWithTimeout("mongodb://"+username+":"+password+"@"+ip+":"+port+"/"+"admin", time.Second*time.Duration(lc.Timeout))
	if err == nil && session.Ping() == nil {
		defer session.Close()
		if err == nil && session.Run("serverStatus", nil) == nil {
			result = true
		}
	}
	return result, err
}

func mongoNullAuth(ip string, port string) (result bool, err error) {
	result = false
	session, err := mgo.Dial(ip + ":" + port)
	if err == nil && session.Run("serverStatus", nil) == nil {
		result = true
	}
	return result, err
}
