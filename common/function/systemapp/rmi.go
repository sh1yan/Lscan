package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"
)

// RmiAttack RMI反序列化攻击函数
func RmiAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int

	if lcc.PortCheck(ip, port, "[RMI]") { // 21端口开放检测，若开放则返回True
		host := fmt.Sprintf("%s:%v", ip, port)
		conn, _ := lcc.WrapperTcpWithTimeout("tcp", host, time.Second*time.Duration(lc.Timeout))
		defer func(conn net.Conn) {
			err := conn.Close()
			if err != nil {

			}
		}(conn)
		_, err := conn.Write([]byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b})
		if err != nil {
			result := fmt.Sprintf("[RMI] %s:%d RMI Registry does not have a deserialization vulnerability!", ip, port)
			logger.Failed(result)
			return
		}
		r1, _ := readRmiBytes(conn)
		if hex.EncodeToString(r1[:1]) == "4e" {
			result := fmt.Sprintf("[RMI] %s:%d RMI Registry Deserialization", ip, port)
			logger.Success(result)
			return
		}
		result := fmt.Sprintf("[RMI] %s:%d RMI Registry does not have a deserialization vulnerability!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[RMI] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

// readRmiBytes 读取字节数据
func readRmiBytes(conn net.Conn) (result []byte, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < 4096 {
			break
		}
	}
	return result, err
}
