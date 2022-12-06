package components

import (
	"Lscan/common/components/logger"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"time"
)

var proxyconn proxy.Dialer
var Timeout time.Duration

func Getconn(ip string, port int) (net.Conn, error) {
	if port == 0 {
		if proxyconn != nil {
			return proxyconn.Dial("tcp", ip)
		} else {
			return net.DialTimeout("tcp", ip, Timeout)
		}
	} else {
		if proxyconn != nil {
			return proxyconn.Dial("tcp", fmt.Sprintf("%v:%v", ip, port))
		} else {
			return net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), Timeout)
		}
	}
}

func IpStringTurnIPClass(ipAddress string) (ip net.IP) {
	// 将string类型的ip地址转换为IP对象

	ip = net.ParseIP(ipAddress)
	if ip == nil {
		result := fmt.Sprintf("Err:无效的地址,%s", ipAddress)
		logger.Error(result)
		return
	}
	return ip
}

func DomainNameTurnIPClass(domain string) (ipAddr *net.IPAddr, ns []string) {
	// 输入域名，返回一个IP地址对象，和一个域名对应多个IP地址列表

	ipAddr, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		result := fmt.Sprintf("Err: %s\n", err.Error())
		logger.Error(result)
		return
	}

	// 域名实际上存在多个IP地址的返回
	ns, err = net.LookupHost(domain)
	if err != nil {
		result := fmt.Sprintf("Err: %s\n", err.Error())
		logger.Error(result)
		return
	}
	return ipAddr, ns
}

func HostAddressTurnTCPAddr(ipAndport string) (ip string, port int) {
	// 将一个host地址转换为TCPAddr。host=ip:port

	pTCPAddr, err := net.ResolveTCPAddr("tcp", ipAndport)
	if err != nil {
		result := fmt.Sprintf("Err: %s", err.Error())
		logger.Error(result)
		return
	}
	return pTCPAddr.IP.String(), pTCPAddr.Port
}
