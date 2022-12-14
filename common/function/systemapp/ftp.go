package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/gftp"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"strconv"
)

var cftp *gftp.FTP // 用于单独连接ftp服务器使用

// FtpAttack FTP口令爆破函数
func FtpAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[FTP]") {  // 21端口开放检测，若开放则返回True
		//Loop: // 定义一个用于跳出循环的label
		for _, user := range lc.UserDict["ftp"] { // 循环遍历出每次ftp需要登录的账号
			for _, pwd := range lc.Passwords { // 循环遍历出每次ftp需要登录的密码
				result := fmt.Sprintf("Check... " + ip + " " + user + " " + pwd) // 输出每次进行登录判断的账号密码
				logger.Verbose(result)
				res, err := ftpAuth(ip, info.ScanPort, user, pwd)
				if res == true && err == nil {
					// PrintIsok2(ScanType, Target, "21", user, pwd)
					result := fmt.Sprintf("[FTP] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					if cftp, err = gftp.Connect(ip + ":" + info.ScanPort); err != nil {
					}
					if err = cftp.Login(user, pwd); err == nil {
						dirs, err := cftp.List("")
						if err == nil {
							if len(dirs) > 0 {
								dirsresult := "FTP-DirsInfo:\n" + lcc.CreatShowSpaceOne() + "[" + logger.LightGreen("*") + "] " + "Current Login: " + user + " - Current Password: " + pwd
								for i := 0; i < len(dirs); i++ {
									dirsinfo := lcc.Delete_extra_space(dirs[i])
									dirsresult += "\n" + lcc.CreatShowSpaceTwo() + "[" + logger.LightGreen("->") + "] " + dirsinfo
								}
								logger.Success(dirsresult)
							}
						}
					}
					return
					// break Loop
				}
			}
		}
		result := fmt.Sprintf("[FTP] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		// FtpScan2(ScanType, Target)
		result := fmt.Sprintf("[FTP] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

// ftpAuth ftp账号密码登录效验
func ftpAuth(ip string, port string, user string, pass string) (result bool, err error) {

	// ip string：192.168.1.1
	// port string：21
	// user string：root
	// pass string：123456

	result = false

	// 定义一个goftp的类对象
	var Lftp *gftp.FTP

	if Lftp, err = gftp.Connect(ip + ":" + port); err != nil {
		// 对目的ip的21端口进行连接，并返回相应自定义的ftp类型数据
		//fmt.Println(err)
	}

	defer Lftp.Close() // 函数运行结束时，关闭FTP连接

	if err = Lftp.Login(user, pass); err == nil {
		// 如果没有错误信息，则说明ftp登录成功
		result = true // 给结果参数进行赋值成功
	}
	return result, err // 若登录失败，则返回失败的结果false，和具体的报错信息
}
