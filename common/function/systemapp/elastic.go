package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"gopkg.in/olivere/elastic.v3"
	"strconv"
)

func ElasticAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[ELASTIC]") {
		for _, user := range lc.UserDict["elastic"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[ELASTIC] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				client, err := elastic.NewClient(elastic.SetURL(fmt.Sprintf("http://%v:%v", ip, port)),
					// elastic.SetMaxRetries(3),
					elastic.SetBasicAuth(user, pwd),
				)
				if err == nil {
					_, _, err = client.Ping(fmt.Sprintf("http://%v:%v", ip, port)).Do()
					if err == nil {
						result := fmt.Sprintf("[ELASTIC] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
						logger.Success(result)
					}
				}

			}
		}
		result := fmt.Sprintf("[ELASTIC] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[ELASTIC] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}
