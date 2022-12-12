package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	"Lscan/configs"
	"fmt"
	"github.com/sh1yan/gohive"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wg
var wg sync.WaitGroup

var lenIpPort int

// 地址管道,1000容量
var addressChan = make(chan string, lenIpPort)
var addressList []string

func workerProbePort() {

	//函数结束wg减1
	defer wg.Done()

	for {
		address, ok := <-addressChan
		if !ok {
			break
		}

		conn, err := lcc.WrapperTcpWithTimeout("tcp", address, time.Second*time.Duration(configs.Timeout))
		if err != nil {
			continue
		}
		conn.Close()
		portString := strings.Split(address, ":")[1]
		portInt, _ := strconv.Atoi(portString)
		pt := lcc.PortDefaultProtocol(portInt)
		result := fmt.Sprintf("open:%s %s[%s]", address, creatSpace(address), pt)
		// [2022.11.25] [+] open:192.168.1.10:445 [Microsoft-DS]

		logger.Success(result)
		addressList = append(addressList, address)

	}
}

// PortScanTcp 参考CSDN网上的并发试端口扫描代码
func PortScanTcp(addre *configs.HostInfo) {
	logger.Info("Start the port survival detection module")
	ip := addre.Hosts
	port := addre.Ports

	if len(configs.HostPort) != 0 { // 用于把从 -hf 中读取的 ip:port 获取效验下，没问题的话，则进行添加该参数进行扫描
		for _, addre := range configs.HostPort {
			addreIpPort := strings.Split(addre, ":")
			if lcc.IsContain(ip, addreIpPort[0]) {
				if !lcc.IsContain(port, addreIpPort[1]) {
					port = append(port, addreIpPort[1]) // 如果该IP为存活IP，且该端口号没有在端口号扫描列表中，则进行追加扫描该端口号
				}
			}
		}
	}
	lenIpPort = len(ip) * len(port) // ip:port 扫描地址管道大小
	logger.Debug(fmt.Sprint("IP address scanning list: ", ip))
	logger.Debug(fmt.Sprint("Port number scanning list: ", port))

	//线程池大小
	var pool_size = configs.ThreadsPortScan
	var pool = gohive.NewFixedSizePool(pool_size)

	//拼接ip:端口
	//启动一个线程,用于生成ip:port,并且存放到地址管道种
	go func() {
		for i := 0; i < len(ip); i++ {
			for r := 0; r < len(port); r++ {
				address := fmt.Sprintf("%s:%s", ip[i], port[r])
				//将address添加到地址管道
				//fmt.Println("<-:",address)
				addressChan <- address
			}
		}
		//发送完关闭 addressChan 管道
		close(addressChan)
	}()

	//启动pool_size工人,处理addressChan种的每个地址
	for work := 0; work < pool_size; work++ {
		wg.Add(1)
		pool.Submit(workerProbePort)

	}

	//等待结束
	wg.Wait()
	addre.HostPortMap = lcc.AddreTurnMap(addressList) // 把 addre.HostPortList 中的主机存活端口列表已map的形式放入到config.HostPortMap中，便于后续功能函数的扫描使用。
	logger.Debug(fmt.Sprint("IP port survival list(addressList):", addressList))
	logger.Debug(fmt.Sprint("IP port survival list(addre.HostPortMap):", addre.HostPortMap))
	resultInfo := fmt.Sprintf("A total of %d port open addres is found this time", len(addressList))
	logger.Info(resultInfo)
}

// creatSpace 增加空格输出
func creatSpace(addres string) string {

	var space string                  // 空格字符串
	var initial = 25                  // 默认最多值
	spaceint := initial - len(addres) // 需要输出的空格数

	for i := 0; i < spaceint; i++ {
		space = space + " "
	}
	return space // 返回需要输出的空格
}
