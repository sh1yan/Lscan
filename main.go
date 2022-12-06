package main

import (
	"Lscan/common/components/logger"
	"Lscan/configs"
	"Lscan/cores"
	"fmt"
	"time"
)

//var ipList = []string{"192.168.43.240", "127.0.0.1"}
//var portList = []string{"80", "445", "443", "139", "135"}

// 目前获取到的本机IP地址与实际ipconfig查询的IP地址不一样，而且获取的IP地址，不支持tcp4的建立监听。

var (
	addre    configs.HostInfo
	instruct configs.CommandInfo
)

func main() {

	start := time.Now()
	cores.Slogan()
	cores.Flag(&addre, &instruct) // 接受外部输入参数
	cores.Scan(&addre, &instruct) // 执行扫描
	t := time.Now().Sub(start)
	result := fmt.Sprintf("Scan completed, total time consumed: %s", t)
	logger.Info(result)
}

func Test1() {

}
