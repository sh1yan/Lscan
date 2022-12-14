package cores

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lcfa "Lscan/common/function/analysis"
	lcfs "Lscan/common/function/systemapp"
	lc "Lscan/configs"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// addScan 调用功能函数公共模块
func addScan(name string, info *lc.HostInfo) {

	if lcc.IsContain(lc.NoScanModularList, name) {
		// 如果在 -nm 中输入了不进行扫描的模块名，则在这里进行处理，进行排除掉这个函数
		return
	}

	f := reflect.ValueOf(lcfa.FuncList[name]) // 通过端口号获取扫描类型，例如 FtpScan,
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in) // 选用第一个例子来说，就是 f.Call(in)  == FtpScan(info)
}

// attackModualScan 攻击扫描模块，使用该模块必须保证前面已经使用过了 PortScanTcp(addre) 功能，且存在一定的存活端口号
func attackModualScan(info *lc.HostInfo) {

	if len(info.HostPortMap) == 0 {
		logger.Error("The current list of IP surviving ports is empty, and vulnerability scanning cannot be performed.")
		return
	}
	logger.Info("Start vulnerability scanning detection module")
	for host, ports := range info.HostPortMap {
		info.ScanHost = host // 给info里的地址覆盖性赋值
		for _, port := range ports {
			info.ScanPort = port
			if _, ok := lcfa.PortForFunc[port]; ok { // 根据对应的端口服务，开启对应的功能扫描
				if strings.Contains(lcfa.PortForFunc[port], ",") { // 该步骤是为了分别取出端口号对应的功能服务
					for _, funcNumber := range strings.Split(lcfa.PortForFunc[port], ",") {
						addScan(funcNumber, info)
						continue
					}
				} else {
					funcNumber := lcfa.PortForFunc[port] // 若该端口号对应只有1个功能服务，则直接使用该服务名
					addScan(funcNumber, info)
					continue
				}
			} else { // 若扫描出来的端口号都不在 lcfa.PortForFunc 中，则开启 webtitle 扫描。
				addScan("webtitle", info)
			}
		}
	}
}

// modualAloneScan 用于扫描特定端口号的模块的函数，该函数只涉及在 entrance.go 中判断模块使用
func modualAloneScan(mnane string, info *lc.HostInfo) {
	// 该模块对应扫描主要针对处理通过flag中使用B，C类单独功能的处理
	if mnane == "survival" { // 该判断主要解决出现多行info输出问题
		lcfs.IpSurvivalScan(info) // 加载IP地址存活扫描
		return
	}

	lcfs.IpSurvivalScan(info) // 加载IP地址存活扫描
	logger.Info(fmt.Sprintf("Start %s scanning detection module", mnane))
	if len(info.Ports) >= 5 { // 若没有-p 输入唯一的端口号，则 addreHandle() 函数会把config中的端口号生成列表，所以该处设置如果端口号大于5，则表示没有输入 ip 参数，故进行反转找对应功能里的默认配置端口号
		// 根据模块名称反找见对应端口号，并进行配置 // 进入该判断表示 -p 等于  0，或端口扫描结果发现未开放端口号
		for port := range lcfa.PortForFunc {
			if lcfa.PortForFunc[port] == mnane {
				info.ScanPort = port
			} else if strings.HasPrefix(lcfa.PortForFunc[port], mnane+",") {
				info.ScanPort = port
			} else if strings.Index(lcfa.PortForFunc[port], ","+mnane+",") != -1 {
				info.ScanPort = port
			} else if strings.HasSuffix(lcfa.PortForFunc[port], ","+mnane) {
				info.ScanPort = port
			}
		}
	} else if len(info.Ports) == 1 { // 判断是否输入了1个 -p 端口号，若是，则进入
		info.ScanPort = info.Ports[0]
	} else { // 若不是，则报错
		result := fmt.Sprint("When the - m parameter is used, multiple port numbers are entered for the - p parameter")
		logger.Error(result)
		os.Exit(0)
	}

	logger.Debug(fmt.Sprint("info.scanport: ", info.ScanPort)) // 用于显示当前自动选择的端口号

	if lcc.IsContain(lc.SpecialIdentifier, info.ScanPort) { // 判断是否为特殊功能,若是则进入下列switch判断
		switch mnane {
		case "webtitle": // 若 -m 输入了 webtitle 则先进行主机存活,再进行端口扫描，最后进行webtitle扫描
			lcfs.PortScanTcp(info)
			modualSelectScan("webtitle", info)
		default:
			logger.Error("Special module writing error, here is a bug")
			return
		}
	} else {
		// 开启对应的模块扫描
		for _, host := range info.Hosts {
			info.ScanHost = host
			addScan(mnane, info)
		}
	}
}

// modualSelectScan 用于手动输入模块名称的自动化扫描，使用该模块必须保证前面已经启动了portscan的扫描，且存在一定的存活端口号
func modualSelectScan(mnane string, info *lc.HostInfo) {
	if len(info.HostPortMap) == 0 {
		logger.Error("The current list of IP surviving ports is empty, and current modual scanning cannot be performed.") // 表示未进行port扫描或者扫描结果为空
		return
	}
	// logger.Info("Start alone function scanning detection module")
	for host, ports := range info.HostPortMap {
		info.ScanHost = host // 给info里的地址覆盖性赋值
		for _, port := range ports {
			info.ScanPort = port
			if _, ok := lcfa.PortForFunc[port]; ok { // 根据对应的端口服务，开启对应的功能扫描
				if strings.Contains(lcfa.PortForFunc[port], ",") { // 该步骤是为了分别取出端口号对应的功能服务
					for _, funcNumber := range strings.Split(lcfa.PortForFunc[port], ",") {
						if funcNumber == mnane { // 判断输入的mnane名称，是否在对应端口开放的服务中
							addScan(funcNumber, info)
							continue
						}
					}
				} else if lcfa.PortForFunc[port] == mnane {
					funcNumber := lcfa.PortForFunc[port] // 若该端口号对应只有1个功能服务，则直接使用该服务名
					addScan(funcNumber, info)
					continue
				}
			} else if mnane == "webtitle" { // 若扫描出来的端口号都不在 lcfa.PortForFunc 中，则判断 mnane 是否为 webtitle ，若是则开启对应扫描。
				addScan(mnane, info)
			}
		}
	}
}
