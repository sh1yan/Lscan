package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"strconv"
	"strings"
	"time"
)

/*

UDP port 137 (name services)

UDP port 138 (datagram services)

TCP port 139 (session services)

*/

// netbioserr 生成一个报错信息
var netbioserr = errors.New("netbios error")

// NetBIOS netbios主运行函数
func NetBIOS(info *lc.HostInfo) error {
	logger.Debug(fmt.Sprint("NetBios -> info.ScanHost: ", info.ScanHost))
	netbios, _ := netBIOS1(info)                                         // 运行 NetBios 功能函数
	output := netbios.String()                                           // 获取扫描结果
	logger.Debug(fmt.Sprint("NetBios -> netbios scan result: ", output)) // 获取扫描结果
	if len(output) > 0 {                                                 // 若存在扫描结果则进行以下输出，否则输出报错信息
		result := fmt.Sprintf("NetBios: %s    %s", info.ScanHost, output)
		logger.Success(result)
		return nil
	}
	return netbioserr
}

// netBIOS1 netbios 主功能函数
func netBIOS1(info *lc.HostInfo) (netbios netBiosInfo, err error) {
	netbios, err = getNbnsname(info)                                     // 获取对应IP地址的计算机服务器名称
	var payload0 []byte                                                  // 定义一个payload的缓存比特数组
	if netbios.ServerService != "" || netbios.WorkstationService != "" { // 若服务器服务或者工作站服务的参数不为空，则赋值到ss中
		ss := netbios.ServerService
		logger.Debug(fmt.Sprint("netbios.ServerService: ", ss))
		if ss == "" {
			ss = netbios.WorkstationService
			logger.Debug(fmt.Sprint("netbios.WorkstationService: ", ss))
		}
		name := netbiosEncode(ss)                                // 编码数据为比特数据
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...) // 组合 payload0
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}
	realhost := fmt.Sprintf("%s:%v", info.ScanHost, info.ScanPort) // 当前主机IP和PORT
	var conn net.Conn
	conn, err = lcc.WrapperTcpWithTimeout("tcp", realhost, time.Duration(lc.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(lc.Timeout) * time.Second)) // SetDeadline 设置与连接相关的读和写的最后期限。
	if err != nil {
		return
	}

	if info.ScanPort == "139" && len(payload0) > 0 { // 判断当前输入IP:PORT中端口是否为139,且上面生成的payload0不为空
		_, err1 := conn.Write(payload0) // 写入payload0的信息,数据中包含ServerService或WorkstationService名称
		if err1 != nil {
			return
		}
		_, err1 = readNerBiosBytes(conn) // 读取比特数据,若程序没报错，则说明正常
		if err1 != nil {
			return
		}
	}

	_, err = conn.Write(negotiateSMBv1Data1) // 写入探测SMBv1的payload数据1
	if err != nil {
		return
	}
	_, err = readNerBiosBytes(conn) // 读取比特数据，判断是否可正常解析
	if err != nil {
		return
	}

	_, err = conn.Write(negotiateSMBv1Data2) // 写入探测SMBv1的payload数据2
	if err != nil {
		return
	}
	var ret []byte
	ret, err = readNerBiosBytes(conn) // 获取响应信息,正常来说发送了 NegotiateSMBv1Data2 数据后,响应的数据中会包含一些 操作系统类型，主机名，netbios名等信息
	if err != nil {
		return
	}
	netbios2, err := parseNTLM(ret)  // 解析数据NTLM认证响应数据，并赋值给netbios2
	joinNetBios(&netbios, &netbios2) // netbios结构体数据合并,并返回合并后的数据结构体
	return
}

// getNbnsname 获取 nbbs 名称 : 获取netbios各类参数
func getNbnsname(info *lc.HostInfo) (netbios netBiosInfo, err error) {
	senddata1 := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1} // 发送数据,获取服务器名称命令字符
	//senddata1 := []byte("ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01")
	realhost := fmt.Sprintf("%s:137", info.ScanHost)                                     // 设置提供计算机的名字或IP地址查询服务的IP地址和端口号
	conn, err := net.DialTimeout("udp", realhost, time.Duration(lc.Timeout)*time.Second) // 创建一个udp连接
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(lc.Timeout) * time.Second)) // 设置连接超时时间
	if err != nil {
		return
	}
	_, err = conn.Write(senddata1) // 发送查询计算机名称命令
	if err != nil {
		return
	}
	text, _ := readNerBiosBytes(conn) // 读取相应的比特数据
	netbios, err = parseNetBios(text) // 把msg中的各类参数赋值给对应名称字符串,并返回 netbios 结构体
	return
}

// bytetoint 比特数据转为int类型数据
func bytetoint(text byte) (int, error) {
	num1 := fmt.Sprintf("%v", text)
	num, err := strconv.Atoi(num1)
	return num, err
}

// 编码算法参考: http://www.manongjc.com/detail/51-ehcwihqnojpmwqo.html
// netbiosEncode 编码字符串数据为netbios格式
func netbiosEncode(name string) (output []byte) {
	var names []int
	src := fmt.Sprintf("%-16s", name)
	for _, a := range src {
		char_ord := int(a)
		high_4_bits := char_ord >> 4 // 位移计算,类似 char_ord / 2
		low_4_bits := char_ord & 0x0f
		names = append(names, high_4_bits, low_4_bits)
	}
	for _, one := range names {
		out := (one + 0x41)
		output = append(output, byte(out))
	}
	return
}

// 以下参考原来: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v%3dtechnet.10)

var (
	// uniqueNames 微软组件使用的独特NetBIOS名称
	uniqueNames = map[string]string{
		"\x00": "WorkstationService",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "ServerService",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	// groupNames 微软组件使用的组NetBIOS名称
	groupNames = map[string]string{
		"\x00": "DomainName",
		"\x1C": "DomainControllers",
		"\x1E": "Browser Service Elections",
	}

	netbiosItemType = map[string]string{
		"\x01\x00": "NetBiosComputerName",
		"\x02\x00": "NetBiosDomainName",
		"\x03\x00": "ComputerName",
		"\x04\x00": "DomainName",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}

	// NTLMSSP challenge 数据

	// 以下SMBV1Data 参考地址: https://github.com/yuriyvolkov/nepenthes/blob/e4069f8145161c3f8431e67003a356fc30bf53a8/modules/vuln-dcom/dcom-shellcodes.h
	/*  NegotiateSMBv1Data1
	ntscan
	=------------------[ hexdump(0x52bfdc10 , 0x00000089) ]-------------------=
	0x0000  00 00 00 85 ff 53 4d 42  72 00 00 00 00 18 53 c8  .....SMB r.....S.
	0x0010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 ff fe  ........ ........
	0x0020  00 00 00 00 00 62 00 02  50 43 20 4e 45 54 57 4f  .....b.. PC NETWO
	0x0030  52 4b 20 50 52 4f 47 52  41 4d 20 31 2e 30 00 02  RK PROGR AM 1.0..
	0x0040  4c 41 4e 4d 41 4e 31 2e  30 00 02 57 69 6e 64 6f  LANMAN1. 0..Windo
	0x0050  77 73 20 66 6f 72 20 57  6f 72 6b 67 72 6f 75 70  ws for W orkgroup
	0x0060  73 20 33 2e 31 61 00 02  4c 4d 31 2e 32 58 30 30  s 3.1a.. LM1.2X00
	0x0070  32 00 02 4c 41 4e 4d 41  4e 32 2e 31 00 02 4e 54  2..LANMA N2.1..NT
	0x0080  20 4c 4d 20 30 2e 31 32  00                        LM 0.12 .
	=-------------------------------------------------------------------------=
	*/

	// negotiateSMBv1Data1 协商SMBV1数据1
	negotiateSMBv1Data1 = []byte{
		0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
		0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
		0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
		0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
		0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
		0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
		0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
	}

	// NegotiateSMBv1Data2参考学习 https://daiker.gitbook.io/windows-protocol/ntlm-pian/4#2.-li-yong-ntlm-jin-hang-de-xin-xi-shou-ji

	// negotiateSMBv1Data2 协商SMBV1数据2
	negotiateSMBv1Data2 = []byte{
		0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
		0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
		0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
		0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
		0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
		0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00, 0x33, 0x00,
		0x20, 0x00, 0x33, 0x00, 0x37, 0x00, 0x39, 0x00, 0x30, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x20, 0x00, 0x50, 0x00, 0x61, 0x00,
		0x63, 0x00, 0x6B, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65, 0x00,
		0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x20, 0x00, 0x32, 0x00, 0x30, 0x00, 0x30, 0x00,
		0x33, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2E, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

// netBiosInfo netbios信息 -> yaml 格式体
type netBiosInfo struct {
	GroupName          string
	WorkstationService string `yaml:"WorkstationService"`
	ServerService      string `yaml:"ServerService"`
	DomainName         string `yaml:"DomainName"`
	DomainControllers  string `yaml:"DomainControllers"`
	ComputerName       string `yaml:"ComputerName"`
	OsVersion          string `yaml:"OsVersion"`
	NetDomainName      string `yaml:"NetBiosDomainName"`
	NetComputerName    string `yaml:"NetBiosComputerName"`
}

// info.String 重构String显示信息
func (info *netBiosInfo) String() (output string) {
	var text string
	var space = "   " // 空格,填充间距

	logger.Debug(fmt.Sprint("NetBios -> ComputerName: ", info.ComputerName))             // debug 获取计算机名称
	logger.Debug(fmt.Sprint("NetBios -> DomainName: ", info.DomainName))                 // debug 域名
	logger.Debug(fmt.Sprint("NetBios -> NetDomainName: ", info.NetDomainName))           // debug 网络域名
	logger.Debug(fmt.Sprint("NetBios -> ServerService: ", info.ServerService))           // debug 服务名称
	logger.Debug(fmt.Sprint("NetBios -> WorkstationService: ", info.WorkstationService)) // debug 工作站服务名称
	logger.Debug(fmt.Sprint("NetBios -> NetComputerName: ", info.NetComputerName))       // debug 网络计算机名称
	logger.Debug(fmt.Sprint("NetBios -> DomainControllers: ", info.DomainControllers))   // debug 域控制器
	logger.Debug(fmt.Sprint("NetBios -> OsVersion: ", info.OsVersion))                   // debug 系统版本

	// ComputerName 信息比较全
	if info.ComputerName != "" {
		if !strings.Contains(info.ComputerName, ".") && info.GroupName != "" { // 若计算机名称不带 . ,且组名称不为空,则进行以下组合
			text = fmt.Sprintf("%s\\%s", info.GroupName, info.ComputerName)
		} else {
			text = fmt.Sprint("ComputerName:", info.ComputerName) // 否则直接输出计算机名称
		}
	} else { // 若计算机名称为空，则进行下列循环
		// 组信息
		if info.DomainName != "" {
			text += info.DomainName
			text += "\\"
		} else if info.NetDomainName != "" {
			text += info.NetDomainName
			text += "\\"
		}
		// 机器名
		if info.ServerService != "" {
			text += info.ServerService
		} else if info.WorkstationService != "" {
			text += info.WorkstationService
		} else if info.NetComputerName != "" {
			text += info.NetComputerName
		}
	}
	if text == "" { // 若上述Text为空，则不处理
	} else if info.DomainControllers != "" {
		output = fmt.Sprintf("[+]DC %-24s", text)
	} else {
		output = fmt.Sprintf("%s", text)
	}
	if info.OsVersion != "" {
		output += space + fmt.Sprint("OsVersion:", info.OsVersion)
	}
	return
}

// parseNetBios 分析NetBios的byte数据:把msg中的netbios信息赋值到对应的结构体中
func parseNetBios(input []byte) (netbios netBiosInfo, err error) {
	if len(input) < 57 {
		err = netbioserr // 若输入的比特大小小于57则说明存在错误,没有数据产生
		return
	}
	data := input[57:] // 获取比特长度57之后的比特数据
	var num int
	num, err = bytetoint(input[56:57][0]) //处理输入的比特56~57之间的数据，把比特数据转换为int数据
	if err != nil {
		return
	}
	var msg string
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flag_bit := data[18*i+15 : 18*i+16]
		if groupNames[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", groupNames[string(flag_bit)], name)
		} else if uniqueNames[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s: %s\n", uniqueNames[string(flag_bit)], name)
		} else if string(flag_bit) == "\x00" || len(data) >= 18*i+18 {
			name_flags := data[18*i+16 : 18*i+18][0]
			if name_flags >= 128 {
				msg += fmt.Sprintf("%s: %s\n", groupNames[string(flag_bit)], name)
			} else {
				msg += fmt.Sprintf("%s: %s\n", uniqueNames[string(flag_bit)], name)
			}
		} else {
			msg += fmt.Sprintf("%s \n", name)
		}
	}
	if len(msg) == 0 {
		err = netbioserr
		return
	}
	err = yaml.Unmarshal([]byte(msg), &netbios) // 判断接受的msg信息流yaml格式数据是否在 &netbios 结构体中，若在则赋值到对应参数下
	if netbios.DomainName != "" {               // 判断当前域名是否不为空
		netbios.GroupName = netbios.DomainName // 把计算机域名赋值给组名称
	}
	return
}

// parseNTLM 解析NTLM认证响应信息
func parseNTLM(ret []byte) (netbios netBiosInfo, err error) {
	if len(ret) < 47 {
		err = netbioserr
		return
	}
	var num1, num2 int
	num1, err = bytetoint(ret[43:44][0])
	if err != nil {
		return
	}
	num2, err = bytetoint(ret[44:45][0])
	if err != nil {
		return
	}
	length := num1 + num2*256
	if len(ret) < 48+length {
		return
	}
	os_version := ret[47+length:]
	tmp1 := bytes.ReplaceAll(os_version, []byte{0x00, 0x00}, []byte{124})
	tmp1 = bytes.ReplaceAll(tmp1, []byte{0x00}, []byte{})
	ostext := string(tmp1[:len(tmp1)-1])
	ss := strings.Split(ostext, "|")
	netbios.OsVersion = ss[0]
	start := bytes.Index(ret, []byte("NTLMSSP"))
	if len(ret) < start+45 {
		return
	}
	num1, err = bytetoint(ret[start+40 : start+41][0])
	if err != nil {
		return
	}
	num2, err = bytetoint(ret[start+41 : start+42][0])
	if err != nil {
		return
	}
	length = num1 + num2*256
	num1, err = bytetoint(ret[start+44 : start+45][0])
	if err != nil {
		return
	}
	offset, err := bytetoint(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return
	}
	var msg string
	index := start + offset
	for index < start+offset+length {
		item_type := ret[index : index+2]
		num1, err = bytetoint(ret[index+2 : index+3][0])
		if err != nil {
			continue
		}
		num2, err = bytetoint(ret[index+3 : index+4][0])
		if err != nil {
			continue
		}
		item_length := num1 + num2*256
		item_content := bytes.ReplaceAll(ret[index+4:index+4+item_length], []byte{0x00}, []byte{})
		index += 4 + item_length
		if string(item_type) == "\x07\x00" {
			//Time stamp, 不需要输出
		} else if netbiosItemType[string(item_type)] != "" {
			msg += fmt.Sprintf("%s: %s\n", netbiosItemType[string(item_type)], string(item_content))
		} else if string(item_type) == "\x00\x00" {
			break
		}
	}
	err = yaml.Unmarshal([]byte(msg), &netbios) // yaml 格式数据匹配
	return
}

// joinNetBios netbios1接收netbios2的参数赋值
func joinNetBios(netbios1, netbios2 *netBiosInfo) *netBiosInfo {
	netbios1.ComputerName = netbios2.ComputerName       // 计算机名称
	netbios1.NetDomainName = netbios2.NetDomainName     // 网络域名
	netbios1.NetComputerName = netbios2.NetComputerName // 网络计算机名称
	if netbios2.DomainName != "" {
		netbios1.DomainName = netbios2.DomainName // 域名
	}
	netbios1.OsVersion = netbios2.OsVersion // 操作系统版本
	return netbios1
}

// readNerBiosBytes 读取比特数据列表
func readNerBiosBytes(conn net.Conn) (result []byte, err error) {
	size := 4096
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < size {
			break
		}
	}
	if len(result) > 0 {
		err = nil
	}
	return result, err
}
