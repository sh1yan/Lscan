package main

import (
	"Lscan/common/components/logger"
	"Lscan/configs"
	"Lscan/cores"
	"fmt"
	"time"
)

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
