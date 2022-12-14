package cores

import (
	"Lscan/common/components/logger"
	lcfa "Lscan/common/function/analysis"
	lc "Lscan/configs"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

// 当前版本信息
var version = "1.0.3"

// logo
var slogan = `

 ...      ...___  ..._____ ...____  ..._ ___
 ...      ...     ...      ...  ___ ..._____
 ___       _____  ___      ________ ________
 ___          ___ ___      ___  ___ ___ ___
 ________ ______   _______ ___  ___ ___  ___

			Lscan version: ` + version + `

`

// Slogan 输出工具logo和版本信息
func Slogan() {

	fmt.Print(slogan)

}

// init 初始化垃圾回收
func init() {
	go func() {
		for {
			GC()
			time.Sleep(10 * time.Second)
		}
	}()
}

// GC 垃圾回收函数
func GC() {
	runtime.GC()         // GC运行一个垃圾回收，并阻塞调用者，直到垃圾回收完成。它也可能阻塞整个程序。
	debug.FreeOSMemory() // FreeOSMemory强制进行垃圾收集，然后尝试尽可能多的内存返回给操作系统。
}

// Flag 接收外部输入参数并进行配置
func Flag(addre *lc.HostInfo, instruct *lc.CommandInfo) {
	flag.StringVar(&addre.ScanHost, "host", "", "IP address of the host you want to scan,for example: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2")
	flag.StringVar(&addre.ScanHost, "h", "", "IP address of the host you want to scan,for example: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2")
	flag.StringVar(&lc.HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&addre.ScanPort, "p", "", "IP port of the host you want to scan,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&lc.PortFile, "pf", "", "Port File")
	flag.StringVar(&instruct.Modular, "m", "", "Select scan modular: survival | portscan | ftp | ssh | find-net | snmp | smb | ms17010 | smbghost | rmi | mssql | oracle | zookeeper | docker | mysql | rdp | postgres | redis | k8s | elastic | memcached | mongodb | webtitle")
	flag.BoolVar(&lc.Ifms, "ifms", false, "stat infoScan")
	flag.BoolVar(&lc.Satt, "satt", false, "stat infoScan and vulScan")
	flag.BoolVar(&lc.Apon, "apon", false, "Enable this setting to scan with full port list")
	flag.StringVar(&lc.OutputFileName, "o", "outcome.txt", "")
	flag.BoolVar(&lc.NoProbe, "np", false, "no probe")
	flag.StringVar(&lc.NoScanModular, "nm", "", "Set the module name not to be scanned")
	flag.IntVar(&lc.ThreadsPortScan, "tps", 1000, "PortScan Thread nums")
	flag.BoolVar(&lc.DnsLog, "dns", false, "using dnslog poc")
	flag.BoolVar(&lc.PocFull, "full", false, "poc full scan,as: shiro 100 key")
	flag.IntVar(&lc.WebTimeout, "wto", 3, "Set web timeout")
	flag.IntVar(&lc.WebThread, "wt", 600, "Set web Thread")
	flag.IntVar(&lc.PocNum, "num", 20, "poc rate")
	flag.StringVar(&lc.Proxy, "proxy", "", "set proxy, -proxy http://127.0.0.1:8080")
	flag.StringVar(&lc.Socks5Proxy, "socks5", "", "set socks5 proxy, will be used in tcp connection, timeout setting will not work")
	flag.StringVar(&lc.Cookie, "cookie", "", "set poc cookie,-cookie rememberMe=login")
	flag.StringVar(&lc.Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic")
	flag.StringVar(&lc.URL, "u", "", "url")
	flag.StringVar(&lc.UrlFile, "uf", "", "urlfile")
	flag.StringVar(&lc.Username, "user", "", "username")
	flag.StringVar(&lc.Password, "pwd", "", "password")
	flag.StringVar(&lc.Userfile, "userf", "", "username file")
	flag.StringVar(&lc.Passfile, "pwdf", "", "password file")
	flag.Int64Var(&lc.Timeout, "time", 3, "Set timeout")
	flag.StringVar(&lc.SC, "sc", "", "ms17 shellcode,as -sc add")
	flag.BoolVar(&lc.IsWebCan, "nopoc", false, "not to scan web vul")
	flag.IntVar(&lc.LogLevel, "logl", 3, "set loglevel")
	flag.Usage = Usage // 输出自定义的 help 信息
	flag.Parse()

	if addre.ScanHost == "" && lc.HostFile == "" && lc.URL == "" && lc.UrlFile == "" { // 若没有输入host内容，则退出程序
		logger.Error(fmt.Sprint("No host addres is entered,Please refer to the following format for input: "))
		flag.Usage() // 输出 help 帮助信息
		os.Exit(0)   // 结束信息
	}
}

// Usage 自定义 help 信息
func Usage() {
	slogan := `
Examples of general usage:
    Lscan.exe -h 192.168.1.1/24                 (Information collection mode scan)
    Lscan.exe -h 192.168.1.1/24 -ifms           (Information collection mode scan)
    Lscan.exe -h 192.168.1.1/24 -satt           (Scan detection mode scan)

Other usage examples:
    Lscan.exe -h 192.168.1.1/24 -m ftp  		 // Batch ftp section blasting scanning for section C
    Lscan.exe -h 192.168.1.1/24 -m survival  	 // Perform survival detection scanning for section C
    Lscan.exe -h 192.168.1.1/24 -m portscan 	 // Open port scanning for section C

Parameter list:
    -host string
          IP address of the host you want to scan,for example: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2
    -hf string
          host file,for example: -hf ip.txt
    -h string
          IP address of the host you want to scan,for example: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2
    -pf string
          Port File,for example: -pf port.txt
    -p string
          IP port of the host you want to scan,for example: 22 | 1-65535 | 22,80,3306
    -ifms
          Start Information Collection Mode Scan
    -satt
          Start scan detection mode scan
    -m string
          Select scan modular: survival | portscan | ftp | ssh | find-net | snmp | smb | ms17010 | smbghost | rmi | mssql | oracle | zookeeper | docker | mysql | rdp | postgres | redis | webtitle | k8s | elastic | memcached | mongodb
    -apon
          Enabling this setting will scan the list of 1~65,535 port numbers with
    -np
          Set not to perform host viability scan
    -nm string
          Set the name of the module that is not scanned, for example: -nm ssh
    -o string
           Set the output path and result name of the scan results (default name outcome.txt)
    -userf string
          username file, for example: -userf user.txt
    -user string
          username
    -pwdf string
          password file, for example: -pwdf pwd.txt
    -pwd string
          password
    -logl int
          Sets the log level, which is used to determine the log level output (default level 3, maximum level can be set to 5)
    -socks5 string
          set socks5 proxy, will be used in tcp connection, timeout setting will not work, for example: -socks5  socks5://127.0.0.1:1080
    -tps int
          Sets the concurrent thread value for the port scan module function (default is 1000)
    -time int
          Set the tcp connection timeout (default 3)

`
	print(slogan)

}

// Scan 工具扫描入口函数
func Scan(addre *lc.HostInfo, icmd *lc.CommandInfo) {
	logger.WriteFile(slogan, lc.OutputFileName)
	logger.Info("Lscan Scanner started")
	lcfa.Parse(addre) // flag参数信息初始化分析设置

	// 执行相关单独的Modular功能函数
	if icmd.Modular != "" {
		// 判断外部输入的modual是否在为有效值
		if _, ok := lcfa.FuncList[icmd.Modular]; ok {
			modualAloneScan(icmd.Modular, addre)
			return
		}
		logger.Error("Module name input error, please re-enter")
		return
	}

	// 执行相关A类参数的一键化功能
	if lc.Ifms == false && lc.Satt == false && icmd.Modular == "" {
		// 若以上两个判断均未执行，则表示没有没有输入B类模块和A类的插件，此时判断是否输入了A类参数，若均没有输入则默认开启信息扫描
		InfoScan(addre)
	} else if lc.Ifms == true && lc.Satt == false {
		InfoScan(addre)
	} else if lc.Satt == true && lc.Ifms == false {
		ScanAttack(addre)
	} else {
		logger.Error("Parameter format input error, please re-enter")
	}

}
