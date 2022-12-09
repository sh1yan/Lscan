package analysis

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Parse 用于所有flag的参数化默认处理配置
func Parse(info *lc.HostInfo) {
	addreHandle(info)        // 处理flag中接收的 -h 和 -p 参数内容
	parseUser()              // 处理flag中接收的 -user 和 -userf 参数内容
	parsePass()              // 处理flag中接收的 -pwd 和 -pwdf 参数内容
	parseUrl()               // 处理flag中接收的 -u 和 -uf 参数内容
	parseComprehensive(info) // 处理flag中
}

// addreHandle 对外置接受的 -h -host -p 参数进行分析，并生成对应的 IP list 和 port list 数据
func addreHandle(addre *lc.HostInfo) {
	/*
		addre.ScanHost 和 addre.ScanPort 接收一开始传递的初值值
		经过 addreHandle() 函数处理，把生成的ip地址列表和port列表放入到 addre.Hosts 和 addre.Ports 中
		最后清空 addre.ScanHost 和 addre.ScanPort 的初始值
	*/
	if lc.HostFile != "" {
		var filehost []string
		filehost, _ = lcc.Readipfile(lc.HostFile) // 读取本地IP列表
		addre.Hosts = filehost                    // 把通过flag读取的本地的ip地址进行放置到 addre.hosts 中

	} else if lcc.ValidationIp(addre.ScanHost) { // 判断flag
		hosts := lcc.ParseHostCreate(addre.ScanHost)
		addre.Hosts = hosts // 把生成好的IP地址放置到 addre.hosts 中
	}

	if lcc.ValidationPort(addre.ScanPort) { // 使用外置输入的端口地址进行扫描
		addre.Ports = lcc.ParsePortCreate(addre.ScanPort)
	} else if lc.PortFile != "" { // 加载本地输入的port文件地址
		ports, err := readfile(lc.PortFile)
		if err == nil {
			newport := ""
			for _, port := range ports {
				if port != "" {
					newport += port + ","
				}
			}
			newport = strings.TrimRight(newport, ",")
			if lcc.ValidationPort(newport) {
				addre.Ports = lcc.ParsePortCreate(newport)
			}
		} else {
			result := fmt.Sprint("端口文件地址路径错误，加载失败")
			logger.Error(result)
			os.Exit(0)
		}
	} else if addre.ScanPort == "" && lc.Apon == true { // 判断初始地址是否为空且效率阈值为关闭状态

		if lcc.ValidationPort(lc.AllPorts) { // 判断非开发者设置的默认端口号地址是否存在不规范的情况

			addre.Ports = lcc.ParsePortCreate(lc.AllPorts)

		} else {
			logger.Error("配置文件中的 configs.AllPorts 设置错误，不符合规范！")
			os.Exit(0)
		}
	} else if addre.ScanPort == "" && lc.Apon == false {

		if lcc.ValidationPort(lc.GeneralPorts) { // 判断非开发者设置的常见默认端口号地址是否存在不规范的情况

			addre.Ports = lcc.ParsePortCreate(lc.GeneralPorts)

		} else {
			logger.Error("配置文件中的 configs.GeneralPorts 设置错误，不符合规范！")
			os.Exit(0)
		}
	} else {
		logger.Error("特殊原因造成端口号未设置成功！")
		os.Exit(0)
	}

	addre.ScanHost = "" // 清空初始化数据
	addre.ScanPort = "" // 清空初始化数据
}

// readfile 文件读取函数
func readfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		result := fmt.Sprintf("Open %s error, %v", filename, err)
		logger.Error(result)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, scanner.Text())
		}
	}
	return content, nil
}

// parseUser 初始化flag中涉及账号的函数
func parseUser() {
	/*
		判断是否存在外部输入的username的ID或外部username的文本文件地址，并保存到 Usernames []string 中。
		最后把获取到的账号ID信息，保存在 lc.UserDict 中。
	*/
	if lc.Username == "" && lc.Userfile == "" {
		return
	}
	var Usernames []string
	if lc.Username != "" {
		Usernames = strings.Split(lc.Username, ",")
	}

	if lc.Userfile != "" {
		users, err := readfile(lc.Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Usernames = append(Usernames, user)
				}
			}
		}
	}

	Usernames = lcc.RemoveDuplicate(Usernames) // 账号ID去重函数
	for name := range lc.UserDict {
		lc.UserDict[name] = Usernames
	}
}

// parsePass 初始化flag中涉及密码的函数
func parsePass() {
	/*
		判断外部输入的passswd和passwd文件地址，传递到 lc.Passwords 中。
		判断外部输入的URL或者URL文件地址，并把url数据传递到 common.Urls  []string 中。
	*/
	var PwdList []string
	if lc.Password != "" {
		passs := strings.Split(lc.Password, ",")
		for _, pass := range passs {
			if pass != "" {
				PwdList = append(PwdList, pass)
			}
		}
		lc.Passwords = PwdList
	}
	if lc.Passfile != "" {
		passs, err := readfile(lc.Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					PwdList = append(PwdList, pass)
				}
			}
			lc.Passwords = PwdList
		}
	}
}

// parseUrl 初始化flag中涉及URL的函数
func parseUrl() {
	if lc.URL != "" {
		urls := strings.Split(lc.URL, ",")
		TmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if _, ok := TmpUrls[url]; !ok {
				TmpUrls[url] = struct{}{}
				if url != "" {
					lc.Urls = append(lc.Urls, url)
				}
			}
		}
	}
	if lc.UrlFile != "" {
		urls, err := readfile(lc.UrlFile)
		if err == nil {
			TmpUrls := make(map[string]struct{})
			for _, url := range urls {
				if _, ok := TmpUrls[url]; !ok {
					TmpUrls[url] = struct{}{}
					if url != "" {
						lc.Urls = append(lc.Urls, url)
					}
				}
			}
		}
	}
}

// parseComprehensive 处理剩余不在以上函数的flag参数内容
func parseComprehensive(info *lc.HostInfo) {

	if lc.Socks5Proxy != "" && !strings.HasPrefix(lc.Socks5Proxy, "socks5://") {
		// 设置socks5代理，将用于tcp连接，超时设置将不起作用
		// 判断代理参数是否为空，且是否以 socks5:// 为开头，若不为空，且未以 socks5:// 为开头，则直接自行添加
		lc.Socks5Proxy = "socks5://" + lc.Socks5Proxy
		lc.NoProbe = true // flag 设置中默认未开启闭禁 ping 扫描
	}

	if lc.NoScanModular != "" {
		var funcNameList []string
		for key, _ := range FuncList {
			funcNameList = append(funcNameList, key)
		}
		logger.Debug(fmt.Sprint("operationHandle.go 214 funcNameList => ", funcNameList))
		nsmodular := strings.Split(lc.NoScanModular, ",")
		for _, val := range nsmodular {
			logger.Debug(fmt.Sprint("operationHandle.go 217 val => ", val))
			if lcc.IsContain(funcNameList, val) {
				lc.NoScanModularList = append(lc.NoScanModularList, val)
				logger.Debug(fmt.Sprint("operationHandle.go 220 lc.NoScanModularList => ", lc.NoScanModularList))
			}
		}
	}

}
