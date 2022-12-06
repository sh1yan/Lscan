package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ZookeeperAttack zookeeper默认访问函数
func ZookeeperAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int

	if lcc.PortCheck(ip, port, "[ZOOKEEPER]") {
		conn, err := lcc.WrapperTcpWithTimeout("tcp", ip+":"+info.ScanPort, time.Duration(lc.Timeout)*time.Second)
		if err != nil {
			return
		}
		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {

			}
		}(conn)

		err = conn.SetWriteDeadline(time.Now().Add(time.Duration(lc.Timeout) * time.Second))
		if err != nil {
			result := fmt.Sprint("[ZOOKEEPER] There is no unauthorized access to zookeeper")
			logger.Failed(result)
			return
		}
		_, err = conn.Write([]byte("envi\r\n"))
		if err != nil {
			result := fmt.Sprint("[ZOOKEEPER] There is no unauthorized access to zookeeper")
			logger.Failed(result)
			return
		}
		err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			result := fmt.Sprint("[ZOOKEEPER] There is no unauthorized access to zookeeper")
			logger.Failed(result)
			return
		}
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString(byte('\n'))
		if !strings.Contains(line, "Environment") {
			result := fmt.Sprint("[ZOOKEEPER] There is no unauthorized access to zookeeper")
			logger.Failed(result)
		}
		// return "zookeeper://" + z.ip + ":" + z.port, err

		result := fmt.Sprintf("[ZOOKEEPER] %s:%d Zookeeper has an unauthorized access vulnerability!", ip, port)
		logger.Success(result)
	} else {
		result := fmt.Sprintf("[ZOOKEEPER] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}
