package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"strconv"
	"time"
)

// SnmpAttack snmp团体名爆破函数
func SnmpAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[SNMP]") {
		for _, community := range lc.UserDict["smb"] {
			result := fmt.Sprintf("[SNMP] Check... " + ip + " " + community)
			logger.Verbose(result)
			gosnmp.Default.Target = ip
			gosnmp.Default.Port = uint16(port)
			gosnmp.Default.Community = community
			gosnmp.Default.Timeout = 3 * time.Second

			err := gosnmp.Default.Connect()
			if err == nil {
				oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
				_, err := gosnmp.Default.Get(oids)
				if err == nil {
					result := fmt.Sprintf("[SNMP] snmp://%s@ %s:%d Password cracked successfully!  ", community, ip, port)
					logger.Success(result)
				}
			}
		}
		result := fmt.Sprintf("[SNMP] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[SNMP] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}
