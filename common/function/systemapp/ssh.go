package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"time"
)

// SshAttack SSH口令破解函数
func SshAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[SSH]") {

		length := len(lc.UserDict["ssh"]) * len(lc.Passwords)
		logger.Debug(fmt.Sprintf("The loading length of the current ssh account password dictionary: %d", length))
		bar := lcc.ProgressDisplay(length, "Wait for ssh password cracking...")
		logger.Warning(fmt.Sprint("To ensure the accuracy of cracking, the current ssh password cracking thread is slow"))
		for _, user := range lc.UserDict["ssh"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[SSH] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result) // 此处存在一个输出bug，即当开启loglevel5时，显示详细输出，进度条会与当前输出处于同一行 -2022.12.8
				res, err := sshAuth(ip, info.ScanPort, user, pwd)
				bar.Add(1)
				if res == true && err == nil {
					fmt.Println() // 用于换行使用，避免使用进程条功能导致信息显示错位
					result := fmt.Sprintf("[SSH] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[SSH] %s:%d Password cracking failed,The password security is high!", ip, port)
		fmt.Println() // 用于换行使用，避免使用进程条功能导致信息显示错位
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[SSH] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func sshAuth(host string, port string, user string, pass string) (result bool, err error) {
	// host string： 192.168.1.240
	// port string： 22
	// user string： root
	// pass string： root

	result = false
	authMethods := []ssh.AuthMethod{}
	// AuthMethod表示RFC 4252身份验证方法的实例。

	// 键盘交互键盘
	// KeyboardInteractiveChallenge应打印问题，可选地禁用回音（例如密码），并返回所有答案。可以在单个会话中多次调用质询。认证成功后，服务器可能会发送一个没有问题的质询，并应打印用户和说明消息。RFC 4256第3.3节详细介绍了用户界面在CLI和GUI环境中的行为。
	keyboardInteractiveChallenge := func(
		user, // 用户名
		instruction string, // 命令
		questions []string, // 问题
		echos []bool, // 输出
	) (answers []string, err error) {
		if len(questions) == 0 { // 判断问题列表是否为空
			return []string{}, nil // 若为空，则直接返回一个空的列表
		}
		return []string{pass}, nil // 返回密码信息
	}

	authMethods = append(authMethods, ssh.KeyboardInteractive(keyboardInteractiveChallenge))
	// KeyboardInteractive使用服务器控制的提示/响应序列返回AuthMethod。
	authMethods = append(authMethods, ssh.Password(pass))
	// Password返回使用给定密码的AuthMethod。

	sshConfig := &ssh.ClientConfig{
		// ClientConfig结构用于配置客户端。在传递给SSH函数后，不能对其进行修改。
		User:    user,
		Auth:    authMethods,
		Timeout: 1 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", host, port), sshConfig)
	// 发送ssh登录信息，并获取连接的客户端信息数据
	if err == nil {
		defer client.Close()                // 本函数运行完后关闭该连接信息
		session, err := client.NewSession() // NewSession为此客户端打开新会话。（会话是程序的远程执行。）
		errRet := session.Run("echo ISOK")
		// 在远程主机上运行cmd。通常，远程服务器将cmd传递给shell进行解释。会话只接受一个调用来运行、启动、Shell、输出或组合输出。
		// 如果命令运行，复制stdin、stdout和stderr没有问题，并且以零退出状态退出，则返回的错误为零。
		// 如果远程服务器未发送退出状态，则返回类型为*ExitMissingError的错误。如果命令未成功完成或被信号中断，则错误类型为*ExitError。对于I/O问题，可能会返回其他错误类型。
		if err == nil && errRet == nil {
			defer session.Close() // 如果信息发送成功，并且无报错信息，返回True，同时关闭session信息。
			result = true
		}
	}
	return result, err
}
