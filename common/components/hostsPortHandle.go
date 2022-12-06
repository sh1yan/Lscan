package components

import (
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"bufio"
	"fmt"
	"github.com/sh1yan/iprange"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ParsePortCreate 函数介绍：主要处理 22,23,80-90,8000-8080 的端口数量.
func ParsePortCreate(ports string) []string {

	var scanPorts []string
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			sort.Strings(ranges)
			port = ranges[0]
			upper = ranges[1]
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			if i < 1 || i > 65535 { // 用于效验去除生成的非法端口号
				continue // 判断输入的端口号是否为非法端口号，若是则跳出循环
			}
			scanPorts = append(scanPorts, strconv.Itoa(i))
		}
	}
	scanPorts = RemoveDuplicate(scanPorts) // 对生成的端口号进行去重处理
	return scanPorts
}

// ParseHostCreate 根据输入的IP地址或段生成对应的IP地址列表，注：使用该函数时请先使用 ValidationIp() 判断下是否符合输入标准
func ParseHostCreate(ips string) []string {
	var hostLists []string
	hostlist, err := iprange.ParseList(ips)
	if err == nil {
		hostsList := hostlist.Expand()
		for _, host := range hostsList {
			host := host.String()
			hostLists = append(hostLists, host)
		}
		return RemoveDuplicate(hostLists) // ip去重
	} else {
		logger.Error("HOST  Host to be scanned, supports four formats: 192.168.1.1 192.168.1.1-10 192.168.1.* 192.168.1.0/24 ")
		os.Exit(0)
	}
	return hostLists
}

// ValidationIp 效验输入的IP地址是否符合工具自身支持的类型，不支持则退出程序,若IP属于程序正常解析范围，则返回true 。
func ValidationIp(hosts string) (rv bool) {

	/* 该正则处理：192.168.1.1、192.168.1.0/24 */
	hostsPattern := `^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\/(\d{1}|[0-2]{1}\d{1}|3[0-2])$|^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$`
	hostsRegexp := regexp.MustCompile(hostsPattern)
	checkHost := hostsRegexp.MatchString(hosts)
	// fmt.Println(checkHost)

	/* 该正则处理：192.168.1.1-10 的IP地址 */
	hostsPattern2 := `\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})\-((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2}))\b`
	hostsRegexp2 := regexp.MustCompile(hostsPattern2)
	checkHost2 := hostsRegexp2.MatchString(hosts)
	// fmt.Println(checkHost2)

	/* 该正则处理：192.168.1.* 的IP地址 */
	hostsPattern3 := `((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(\*$)`
	hostsRegexp3 := regexp.MustCompile(hostsPattern3)
	checkHost3 := hostsRegexp3.MatchString(hosts)
	// fmt.Println(checkHost3)

	if hosts == "" || (checkHost == false && checkHost2 == false && checkHost3 == false) {
		logger.Error("Host to be scanned, supports four formats: 192.168.1.1 192.168.1.1-10 192.168.1.* 192.168.1.0/24 ")
		os.Exit(0)
	}

	_, err := iprange.ParseList(hosts)
	if err != nil {
		logger.Error("Host to be scanned, supports four formats: 192.168.1.1 192.168.1.1-10 192.168.1.* 192.168.1.0/24 ")
		os.Exit(0)
	}
	return true
}

// ValidationPort 效验输入的端口是否符合工具自身支持的类型，不支持则退出程序，若输入工具正常解析范围则返回 true
func ValidationPort(ports string) (rv bool) {

	/* 该正则处理：21,22,80-99,8000-8080 */
	portsPattern := `^([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$|^\d+(-\d+)?(,\d+(-\d+)?)*$`
	portsRegexp := regexp.MustCompile(portsPattern)
	checkPort := portsRegexp.MatchString(ports)
	// fmt.Println(checkPort)
	if ports != "" && checkPort == false {
		logger.Error("PORT Error.  Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...")
		os.Exit(0)
		return false
	} else if ports == "" {
		// 如果参数端口号列表为空，则直接返回 false
		return false
	}
	return true
}

// RemoveDuplicate 去除重复项
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// IsContain 判断 item 是否在 items 中
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// 按行读ip
func Readipfile(filename string) ([]string, error) {
	file, err := os.Open(filename) // 打开文件数据流
	if err != nil {
		result := fmt.Sprintf("Open %s error, %v", filename, err)
		logger.Error(result)
		os.Exit(0)
	}
	defer file.Close() // 函数结束时，关闭文件
	var content []string
	scanner := bufio.NewScanner(file) // 数据流格式更新为 *bufio.Scanner 格式
	scanner.Split(bufio.ScanLines)    // 对数据流按照行进行分割
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			text := strings.Split(line, ":")
			if len(text) == 2 { // 此处判断接收的以分号分割的数组是否长度为2
				port := strings.Split(text[1], " ")[0] // 若为2，则取出端口号的值
				num, err := strconv.Atoi(port)         // 端口号转成 int 类型的数据
				if err != nil || (num < 1 || num > 65535) {
					continue // 判断输入的端口号是否为非法端口号，若是则跳出循环
				}
				hosts := ParseIPs(text[0]) // 对接收的IP字符串进行多种格式分析，最终输出成 hosts []string 形式的IP地址列表
				for _, host := range hosts {
					lc.HostPort = append(lc.HostPort, fmt.Sprintf("%s:%s", host, port)) // 拼接为 host:port 形式
					content = append(content, host)                                     // 放置到本函数体内定义的 []string 中
				}
			} else { // 若只是单纯的IP，则进行以下步骤处理
				host := ParseIPs(line)             // 对接收的IP字符串进行多种格式分析，最终输出成 hosts []string 形式的IP地址列表
				content = append(content, host...) // 放置到本函数体内定义的 []string 中
			}
		}
	}
	content = RemoveDuplicate(content)
	return content, nil // 等函数体都运行完毕后，返回单独的ip []string，而特殊的 host:port 形式数据，则放到对应的数据中
}

// ParseIPs 对接收的IP字符串进行多种格式分析，最终输出成 hosts []string 形式的IP地址列表
func ParseIPs(ip string) (hosts []string) {

	if strings.Contains(ip, ",") { // 判断传入的ip是否为ip地址段，并且以逗号作为分割
		IPList := strings.Split(ip, ",") // 以逗号为分割，生成一个 []string 的数组
		var ips []string
		for _, ip := range IPList {
			if ValidationIp(ip) {
				ips = ParseHostCreate(ip)     // 处理接收的IP地址，进行格式分析，并最终输出 []string 形式的切片数组
				hosts = append(hosts, ips...) // IP地址切片追加数据
			}
		}
	} else {
		if ValidationIp(ip) {
			hosts = ParseHostCreate(ip) // 对非直接逗号的IP地址，进行格式分析，并最终输出 []string 形式的切片数组
		}
	}
	return hosts
}

// AddreTurnMap 用于把扫描出的存活的IP:PORT按照map的形式存放,并输出返回值
func AddreTurnMap(hostPort []string) map[string][]string {
	tmpHostPortMap := make(map[string][]string)
	for _, i := range hostPort {
		ipPortStrList := strings.Split(i, ":")
		ip := ipPortStrList[0]
		port := ipPortStrList[1]
		if _, ok := tmpHostPortMap[ip]; ok {
			tmpPorts := tmpHostPortMap[ip]                     // 取出当前临时 tmpHostPortMap[ip] 的端口号列表
			tmpPorts = RemoveDuplicate(append(tmpPorts, port)) // 增加数据并去下重，防止出现重复端口
			tmpHostPortMap[ip] = tmpPorts                      // 覆盖式赋值
		} else {
			tmpHostPortMap[ip] = append(tmpHostPortMap[ip], port) // 当前地址端口未在map中出现，直接赋值
		}
	}
	return tmpHostPortMap
}
