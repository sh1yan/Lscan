package systemapp

import (
	lcc "Lscan/common/components"
	lcci "Lscan/common/components/icmp"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	ipAddreList []string // 临时存放存活主机的地址
	existHosts  = make(map[string]struct{})
	livewg      sync.WaitGroup
)

// IpSurvivalScan 主机存活扫描
func IpSurvivalScan(addre *lc.HostInfo) {
	if lc.NoProbe {
		logger.Info("No probe, use all hosts")
		// 若启动禁ping设置，则不进行主机存活扫描，直接开始下一个环境的扫描
		return
	}
	logger.Info("Start the host survival detection module")
	ipAddreList = addre.Hosts // 扫描地址列表赋值到一个临时表单中
	logger.Debug(fmt.Sprint("IP survival scanning address list: ", ipAddreList))
	addre.Hosts = []string{}                         // 清空 addre.hosts 中 IP 地址列表
	chanHosts := make(chan string, len(ipAddreList)) // 创建一个主机IP列表的管道
	go func() { // 用于接受主机存活结果的并发线程
		for ip := range chanHosts {
			if _, ok := existHosts[ip]; !ok && lcc.IsContain(ipAddreList, ip) { // 判断ip是已经探测过，若没探测过，且这个IP在地址列表中则进入下一个环节。
				existHosts[ip] = struct{}{} // 放入到map中
				result := fmt.Sprintf("Target %s is alive", ip)
				logger.Success(result)
				addre.Hosts = append(addre.Hosts, ip) // 存活主机放入到 alivehosts 中
			}
			livewg.Done()
		}
	}()

	conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", time.Duration(lc.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		logger.Debug("Use the runIcmp function to perform ICMP host survival scanning")
		runIcmp(ipAddreList, chanHosts)
	} else {
		logger.LogError(err)
		//使用ping探测
		logger.Debug("The current user permissions unable to send icmp packets")
		logger.Debug("Use the system ping to perform host survival scanning")
		runPing(ipAddreList, chanHosts)
	}

	livewg.Wait()    // 等待管道结果输出结束
	close(chanHosts) // 关闭结果输出管道

	result := fmt.Sprintf("A total of %d surviving host is found this time", len(addre.Hosts))
	logger.Info(result)
}

// runIcmp 多线程使用icmp函数来探测存活
func runIcmp(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if lcci.Icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

// runPing 使用系统自带的ping进行存活扫描
func runPing(hostslist []string, chanHosts chan string) {

	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if lcc.PingSystem(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}
