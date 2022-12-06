package components

import (
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"strconv"
	"time"
)

// Portcheck 判断当前IP地址端口是否开放
func PortCheck(host string, port int, vtype string) bool {
	p := strconv.Itoa(port)
	conn, err := WrapperTcpWithTimeout("tcp", host+":"+p, time.Second*time.Duration(lc.Timeout))
	if err != nil {
		return false
	} else {
		result := fmt.Sprintf("%s IP：%s PORT：%d STATE：Open ", vtype, host, port)
		logger.Common(result)
		conn.Close()
		return true
	}
}
