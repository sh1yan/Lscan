package components

// 代码源地址：https://github.com/dutchcoders/goftp/blob/v1/ftp.go

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FTP RFC 959中定义的状态代码
const (
	StatusFileOK                = "150"
	StatusOK                    = "200"
	StatusSystemStatus          = "211"
	StatusDirectoryStatus       = "212"
	StatusFileStatus            = "213"
	StatusConnectionClosing     = "221"
	StatusSystemType            = "215"
	StatusClosingDataConnection = "226"
	StatusActionOK              = "250"
	StatusPathCreated           = "257"
	StatusActionPending         = "350"
)

var statusText = map[string]string{
	StatusFileOK:                "File status okay; about to open data connection",            // 文件状态正常；即将打开数据连接
	StatusOK:                    "Command okay",                                               // 命令行输入正确
	StatusSystemStatus:          "System status, or systemapp help reply",                     // 系统状态或系统帮助回复
	StatusDirectoryStatus:       "Directory status",                                           // 目录状态
	StatusFileStatus:            "File status",                                                // 文件状态
	StatusConnectionClosing:     "Service closing control connection",                         // 服务关闭控制连接
	StatusSystemType:            "System Type",                                                // 系统类型
	StatusClosingDataConnection: "Closing data connection. Requested file action successful.", // 正在关闭数据连接。请求的文件操作成功
	StatusActionOK:              "Requested file action okay, completed",                      // 请求的文件操作正常，已完成
	StatusPathCreated:           "Pathname Created",                                           // 已创建路径名
	StatusActionPending:         "Requested file action pending further information",          // 请求的文件操作正在等待进一步信息
}

// StatusText 返回FTP状态代码的文本。它返回空值
// 字符串，如果代码未知。
func StatusText(code string) string {
	return statusText[code]
}

// RePwdPath 是当前工作目录中匹配文件的默认表达式
var RePwdPath = regexp.MustCompile(`\"(.*)\"`)

// FTP 是用于文件传输协议的会话
type FTP struct {
	conn net.Conn

	addr string

	debug     bool
	tlsconfig *tls.Config

	reader *bufio.Reader
	writer *bufio.Writer
}

// Close 结束FTP连接
func (ftp *FTP) Close() error {
	return ftp.conn.Close()
}

type (
	// WalkFunc 在行走中的每条路径上调用。通过WalkFunc过滤错误
	WalkFunc func(path string, info os.FileMode, err error) error

	// RetrFunc 被传递给Retr，并且是针对给定路径接收的流的处理程序
	RetrFunc func(r io.Reader) error
)

func parseLine(line string) (perm string, t string, filename string) {
	for _, v := range strings.Split(line, ";") {
		v2 := strings.Split(v, "=")

		switch v2[0] {
		case "perm":
			perm = v2[1]
		case "type":
			t = v2[1]
		default:
			filename = v[1 : len(v)-2]
		}
	}
	return
}

// Walk 递归遍历路径并为每个文件调用walkfunc
func (ftp *FTP) Walk(path string, walkFn WalkFunc) (err error) {
	/*
		if err = walkFn(path, os.ModeDir, nil); err != nil {
			if err == filepath.SkipDir {
				return nil
			}
		}
	*/
	if ftp.debug {
		log.Printf("Walking: '%s'\n", path)
	}

	var lines []string

	if lines, err = ftp.List(path); err != nil {
		return
	}

	for _, line := range lines {
		_, t, subpath := parseLine(line)

		switch t {
		case "dir":
			if subpath == "." {
			} else if subpath == ".." {
			} else {
				if err = ftp.Walk(path+subpath+"/", walkFn); err != nil {
					return
				}
			}
		case "file":
			if err = walkFn(path+subpath, os.FileMode(0), nil); err != nil {
				return
			}
		}
	}

	return
}

// Quit 将quit发送到服务器并关闭连接。在此之后无需关闭。
func (ftp *FTP) Quit() (err error) {
	if _, err := ftp.cmd(StatusConnectionClosing, "QUIT"); err != nil {
		return err
	}

	ftp.conn.Close()
	ftp.conn = nil

	return nil
}

// Noop 将向服务器发送NOOP（无操作）
func (ftp *FTP) Noop() (err error) {
	_, err = ftp.cmd(StatusOK, "NOOP")
	return
}

// RawCmd 将原始命令发送到远程服务器。将响应代码返回为int，将响应返回为string。
func (ftp *FTP) RawCmd(command string, args ...interface{}) (code int, line string) {
	if ftp.debug {
		log.Printf("Raw-> %s\n", fmt.Sprintf(command, args...))
	}

	code = -1
	var err error
	if err = ftp.send(command, args...); err != nil {
		return code, ""
	}
	if line, err = ftp.receive(); err != nil {
		return code, ""
	}
	code, err = strconv.Atoi(line[:3])
	if ftp.debug {
		log.Printf("Raw<-	<- %d \n", code)
	}
	return code, line
}

// 用于发送命令并将返回代码与预期值进行比较的专用函数
func (ftp *FTP) cmd(expects string, command string, args ...interface{}) (line string, err error) {
	// expects string ：该参数接受标识符值，从Login函数中进来的数据为  "331"
	// command string ：该参数接受ftp命令值，从Login函数中进来的数据为  "USER %s"
	// args ...interface{} ：该类型接受万能类型，从Login函数中进来的数据为 username

	if err = ftp.send(command, args...); err != nil {
		// send 函数默认返回为空的，为空即为正常发送数据，为不为空则返回的为err报错信息，意味着发送数据失败。
		return
	}

	if line, err = ftp.receive(); err != nil {
		// 获取响应数据流的字符串形式
		return
	}

	if !strings.HasPrefix(line, expects) { // 若登录失败则进入该局部代码
		// HasPrefix测试字符串s是否以前缀开头。
		// line：传递获取的数据流的字符串值，主要为21端口发送完命令的返回信息
		// expects：从Login函数中进来的数据为 "331"，如果登录成功，则响应的数据信息是以331开头显示

		err = errors.New(line)
		// New返回一个错误，格式为给定文本。每次调用New都会返回一个不同的错误值，即使文本相同。
		return
	}

	return
}

// Rename 远程主机上的文件
func (ftp *FTP) Rename(from string, to string) (err error) {
	if _, err = ftp.cmd(StatusActionPending, "RNFR %s", from); err != nil {
		return
	}

	if _, err = ftp.cmd(StatusActionOK, "RNTO %s", to); err != nil {
		return
	}

	return
}

// Mkd 在远程主机上创建目录
func (ftp *FTP) Mkd(path string) error {
	_, err := ftp.cmd(StatusPathCreated, "MKD %s", path)
	return err
}

// Rmd 删除目录
func (ftp *FTP) Rmd(path string) (err error) {
	_, err = ftp.cmd(StatusActionOK, "RMD %s", path)
	return
}

// Pwd 获取远程主机上的当前路径
func (ftp *FTP) Pwd() (path string, err error) {
	var line string
	if line, err = ftp.cmd(StatusPathCreated, "PWD"); err != nil {
		return
	}

	res := RePwdPath.FindAllStringSubmatch(line[4:], -1)

	path = res[0][1]
	return
}

// Cwd 将远程主机上的当前工作目录更改为路径
func (ftp *FTP) Cwd(path string) (err error) {
	_, err = ftp.cmd(StatusActionOK, "CWD %s", path)
	return
}

// Dele 删除远程主机上的路径
func (ftp *FTP) Dele(path string) (err error) {
	if err = ftp.send("DELE %s", path); err != nil {
		return
	}

	var line string
	if line, err = ftp.receive(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusActionOK) {
		return errors.New(line)
	}

	return
}

// AuthTLS 通过使用TLS保护ftp连接
func (ftp *FTP) AuthTLS(config *tls.Config) error {
	if _, err := ftp.cmd("234", "AUTH TLS"); err != nil {
		return err
	}

	// 在现有连接上包裹tls
	ftp.tlsconfig = config

	ftp.conn = tls.Client(ftp.conn, config)
	ftp.writer = bufio.NewWriter(ftp.conn)
	ftp.reader = bufio.NewReader(ftp.conn)

	if _, err := ftp.cmd(StatusOK, "PBSZ 0"); err != nil {
		return err
	}

	if _, err := ftp.cmd(StatusOK, "PROT P"); err != nil {
		return err
	}

	return nil
}

// ReadAndDiscard 读取所有缓冲的字节并返回字节数
// 从缓冲区中清除
func (ftp *FTP) ReadAndDiscard() (int, error) {
	var i int
	bufferSize := ftp.reader.Buffered() // Buffered返回可从当前缓冲区读取的字节数。
	for i = 0; i < bufferSize; i++ {
		if _, err := ftp.reader.ReadByte(); err != nil {
			// ReadByte读取并返回单个字节。如果没有可用字节，则返回错误。
			// 丢失掉读取的缓存字节数据
			return i, err
		}
	}
	return i, nil
}

// Type 更改传输类型。
func (ftp *FTP) Type(t TypeCode) error {
	_, err := ftp.cmd(StatusOK, "TYPE %s", t)
	return err
}

// TypeCode 用于表示类型
type TypeCode string

const (
	// TypeASCII for ASCII
	TypeASCII = "A"
	// TypeEBCDIC for EBCDIC
	TypeEBCDIC = "E"
	// TypeImage for an Image
	TypeImage = "I"
	// TypeLocal for local byte size
	TypeLocal = "L"
)

// receiveLine 数据流量接收并按照字符格式进行传递
func (ftp *FTP) receiveLine() (string, error) {
	line, err := ftp.reader.ReadString('\n')
	// ReadString一直读取到输入中第一次出现delim，返回一个包含数据的字符串，直到并包括分隔符。如果ReadString在查找分隔符之前遇到错误，它将返回错误之前读取的数据和错误本身（通常是io.EOF）。ReadString返回错误！=nil当且仅当返回的数据不以delim结尾。对于简单的使用，扫描仪可能更方便。

	if ftp.debug { // 判断是否开启debug，若开启，则对每个读取的流量进行一个日志输出！
		log.Printf("< %s", line)
	}

	return line, err
}

// receive 数据流接收处理函数
func (ftp *FTP) receive() (string, error) {
	line, err := ftp.receiveLine() // 返回字符串形式的数据流量

	if err != nil {
		return line, err
	}

	if (len(line) >= 4) && (line[3] == '-') {
		// 判断长度是否大于4并且第4位是否为 - ，若是则确认数据流为多行数据
		// 多行响应处理流程
		closingCode := line[:3] + " " // 根据流量生成特定的闭合码
		for {
			str, err := ftp.receiveLine() // 对流量进行重新读取
			line = line + str             // 闭合码 + 流量字符 = 组合为一个新的字符信息流
			if err != nil {
				return line, err // 如果出现报错，则抛出异常信息和数据
			}
			if len(str) < 4 { // 如果获取的字符数据流为小于4的，则判断是否开启debug模式，若开启，则说明当前数据流未正确终止响应！
				if ftp.debug {
					log.Println("Uncorrectly terminated response") // 未正确终止的响应
				}
				break // 终止该for循环
			} else {
				if str[:4] == closingCode { // 若for循环外围的数据流闭合码与内for循环的闭合码相一致，则退出当前for循环！
					break
				}
			}
		}
	}
	ftp.ReadAndDiscard() // 清除缓存的字节数据
	//fmt.Println(line)
	return line, err
}

func (ftp *FTP) receiveNoDiscard() (string, error) {
	line, err := ftp.receiveLine()

	if err != nil {
		return line, err
	}

	if (len(line) >= 4) && (line[3] == '-') {
		//Multiline response
		closingCode := line[:3] + " "
		for {
			str, err := ftp.receiveLine()
			line = line + str
			if err != nil {
				return line, err
			}
			if len(str) < 4 {
				if ftp.debug {
					log.Println("Uncorrectly terminated response")
				}
				break
			} else {
				if str[:4] == closingCode {
					break
				}
			}
		}
	}
	//ftp.ReadAndDiscard()
	//fmt.Println(line)
	return line, err
}

// send 对接受过来的命令和参数，写入到对应的端口数据包里
func (ftp *FTP) send(command string, arguments ...interface{}) error {
	// command string： 该参数接受ftp命令值，从Login函数中进来的数据为  "USER %s"
	// arguments ...interface{} ：该类型接受万能类型，从Login函数中进来的数据为 username

	if ftp.debug { // 判断是否开启Debug模式，若开启则输出命令信息
		log.Printf("> %s", fmt.Sprintf(command, arguments...))
	}

	command = fmt.Sprintf(command, arguments...) // 从login函数中结束的命令进行拼接：USER %s username "\r\n" // 这里去掉双引号
	command += "\r\n"

	if _, err := ftp.writer.WriteString(command); err != nil { // 把命令写入到21端口的数据流中
		return err
	}

	if err := ftp.writer.Flush(); err != nil { // Flush将所有缓冲数据写入基础io.Writer。
		return err
	}

	return nil
}

// Pasv 启用被动数据连接并返回端口号
func (ftp *FTP) Pasv() (port int, err error) {
	doneChan := make(chan int, 1)
	go func() {
		defer func() {
			doneChan <- 1
		}()
		var line string
		if line, err = ftp.cmd("227", "PASV"); err != nil {
			return
		}
		re := regexp.MustCompile(`\((.*)\)`)
		res := re.FindAllStringSubmatch(line, -1)
		if len(res) == 0 || len(res[0]) < 2 {
			err = errors.New("PasvBadAnswer")
			return
		}
		s := strings.Split(res[0][1], ",")
		if len(s) < 2 {
			err = errors.New("PasvBadAnswer")
			return
		}
		l1, _ := strconv.Atoi(s[len(s)-2])
		l2, _ := strconv.Atoi(s[len(s)-1])

		port = l1<<8 + l2

		return
	}()

	select {
	case _ = <-doneChan:

	case <-time.After(time.Second * 10):
		err = errors.New("PasvTimeout")
		ftp.Close()
	}

	return
}

// newConnection 打开新数据连接
func (ftp *FTP) newConnection(port int) (conn net.Conn, err error) {
	addr := fmt.Sprintf("%s:%d", strings.Split(ftp.addr, ":")[0], port)

	if ftp.debug {
		log.Printf("Connecting to %s\n", addr)
	}

	if conn, err = net.Dial("tcp", addr); err != nil {
		return
	}

	if ftp.tlsconfig != nil {
		conn = tls.Client(conn, ftp.tlsconfig)
	}

	return
}

// Stor 从r将文件上载到远程主机路径
func (ftp *FTP) Stor(path string, r io.Reader) (err error) {
	if err = ftp.Type(TypeImage); err != nil {
		return
	}

	var port int
	if port, err = ftp.Pasv(); err != nil {
		return
	}

	if err = ftp.send("STOR %s", path); err != nil {
		return
	}

	var pconn net.Conn
	if pconn, err = ftp.newConnection(port); err != nil {
		return
	}
	defer pconn.Close()

	var line string
	if line, err = ftp.receive(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusFileOK) {
		err = errors.New(line)
		return
	}

	if _, err = io.Copy(pconn, r); err != nil {
		return
	}
	pconn.Close()

	if line, err = ftp.receive(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusClosingDataConnection) {
		err = errors.New(line)
		return
	}

	return

}

// Syst 返回远程主机的系统类型
func (ftp *FTP) Syst() (line string, err error) {
	if err := ftp.send("SYST"); err != nil {
		return "", err
	}
	if line, err = ftp.receive(); err != nil {
		return
	}
	if !strings.HasPrefix(line, StatusSystemType) {
		err = errors.New(line)
		return
	}

	return strings.SplitN(strings.TrimSpace(line), " ", 2)[1], nil
}

// 用于System的系统类型
var (
	SystemTypeUnixL8    = "UNIX Type: L8"
	SystemTypeWindowsNT = "Windows_NT"
)

var reSystStatus = map[string]*regexp.Regexp{
	SystemTypeUnixL8:    regexp.MustCompile(""),
	SystemTypeWindowsNT: regexp.MustCompile(""),
}

// Stat 从远程主机获取路径的状态
func (ftp *FTP) Stat(path string) ([]string, error) {
	if err := ftp.send("STAT %s", path); err != nil {
		return nil, err
	}

	stat, err := ftp.receive()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(stat, StatusFileStatus) &&
		!strings.HasPrefix(stat, StatusDirectoryStatus) &&
		!strings.HasPrefix(stat, StatusSystemStatus) {
		return nil, errors.New(stat)
	}
	if strings.HasPrefix(stat, StatusSystemStatus) {
		return strings.Split(stat, "\n"), nil
	}
	lines := []string{}
	for _, line := range strings.Split(stat, "\n") {
		if strings.HasPrefix(line, StatusFileStatus) {
			continue
		}
		//fmt.Printf("%v\n", re.FindAllStringSubmatch(line, -1))
		lines = append(lines, strings.TrimSpace(line))

	}
	// TODO(vbatts) parse this line for SystemTypeWindowsNT
	//"213-status of /remfdata/all.zip:\r\n    09-12-15  04:07AM             37192705 all.zip\r\n213 End of status.\r\n"

	// and this for SystemTypeUnixL8
	// "-rw-r--r--   22 4015     4015        17976 Jun 10  1994 COPYING"
	// "drwxr-xr-x    6 4015     4015         4096 Aug 21 17:25 kernels"
	return lines, nil
}

// Retr 在路径处从远程主机检索文件，使用retrFn从远程文件读取。
func (ftp *FTP) Retr(path string, retrFn RetrFunc) (s string, err error) {
	if err = ftp.Type(TypeImage); err != nil {
		return
	}

	var port int
	if port, err = ftp.Pasv(); err != nil {
		return
	}

	if err = ftp.send("RETR %s", path); err != nil {
		return
	}

	var pconn net.Conn
	if pconn, err = ftp.newConnection(port); err != nil {
		return
	}
	defer pconn.Close()

	var line string
	if line, err = ftp.receiveNoDiscard(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusFileOK) {
		err = errors.New(line)
		return
	}

	if err = retrFn(pconn); err != nil {
		return
	}

	pconn.Close()

	if line, err = ftp.receive(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusClosingDataConnection) {
		err = errors.New(line)
		return
	}

	return
}

/*func GetFilesList(path string) (files []string, err error) {

}*/

// List 列出路径（或当前目录）
func (ftp *FTP) List(path string) (files []string, err error) {
	if err = ftp.Type(TypeASCII); err != nil {
		return
	}

	var port int
	if port, err = ftp.Pasv(); err != nil {
		return
	}

	// 检查MLSD是否工作
	if err = ftp.send("MLSD %s", path); err != nil {
	}

	var pconn net.Conn
	if pconn, err = ftp.newConnection(port); err != nil {
		return
	}
	defer pconn.Close()

	var line string
	if line, err = ftp.receiveNoDiscard(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusFileOK) {
		// MLSD失败，让我们尝试列表
		if err = ftp.send("LIST %s", path); err != nil {
			return
		}

		if line, err = ftp.receiveNoDiscard(); err != nil {
			return
		}

		if !strings.HasPrefix(line, StatusFileOK) {
			// 真的吗？列表在这里不起作用
			err = errors.New(line)
			return
		}
	}

	reader := bufio.NewReader(pconn)

	for {
		line, err = reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return
		}

		files = append(files, string(line))
	}
	// 必须关闭vsftp tlsed连接，否则无法接收连接
	pconn.Close()

	if line, err = ftp.receive(); err != nil {
		return
	}

	if !strings.HasPrefix(line, StatusClosingDataConnection) {
		err = errors.New(line)
		return
	}

	return
}

/*


// 以奇怪的登录行为登录服务器
func (ftp *FTP) SmartLogin(username string, password string) (err error) {
	var code int
	// 也许服务器有一些无用的话要说。让他说话
	code, _ = ftp.RawCmd("NOOP")

	if code == 220 || code == 530 {
		// 也许在另一个Noop中，服务器会要求我们登录？
		code, _ = ftp.RawCmd("NOOP")
		if code == 530 {
			// ok, let's login
			code, _ = ftp.RawCmd("USER %s", username)
			code, _ = ftp.RawCmd("NOOP")
			if code == 331 {
				// user accepted, password required
				code, _ = ftp.RawCmd("PASS %s", password)
				code, _ = ftp.RawCmd("PASS %s", password)
				if code == 230 {
					code, _ = ftp.RawCmd("NOOP")
					return
				}
			}
		}

	}
	// 没什么奇怪的…让我们尝试正常登录
	return ftp.Login(username, password)
}

*/

// Login 使用提供的用户名和密码发送到服务器。
// 典型的默认值可能是（“username”、“password”）。
func (ftp *FTP) Login(username string, password string) (err error) {
	if _, err = ftp.cmd("331", "USER %s", username); err != nil {
		//
		if strings.HasPrefix(err.Error(), "230") {
			// 好的，可能是匿名服务器
			// 但是登录很好，所以没有返回错误
			err = nil
		} else {
			return
		}
	}

	if _, err = ftp.cmd("230", "PASS %s", password); err != nil {
		return
	}

	return
}

// Connect 到addr的服务器（格式为“ip:port”）。调试已关闭
func Connect(addr string) (*FTP, error) {
	var err error
	var conn net.Conn

	if conn, err = net.Dial("tcp", addr); err != nil {
		return nil, err
	}

	writer := bufio.NewWriter(conn)
	// NewWriter返回缓冲区大小为默认值的新写入程序。如果参数为io。Writer已经是一个缓冲区大小足够大的Writer，它返回基础Writer。
	reader := bufio.NewReader(conn)
	// NewReader返回缓冲区具有默认大小的新读取器。

	//reader.ReadString('\n')
	object := &FTP{conn: conn, addr: addr, reader: reader, writer: writer, debug: false} // 按照固定格式把数据传入到ftp对象类中
	object.receive()                                                                     // 对获取的数据流信息，已字符串的形式返回

	return object, nil
}

// ConnectDbg 到addr的服务器（格式为“主机：端口”）。调试已打开
func ConnectDbg(addr string) (*FTP, error) {
	var err error
	var conn net.Conn

	if conn, err = net.Dial("tcp", addr); err != nil {
		return nil, err
	}

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	var line string

	object := &FTP{conn: conn, addr: addr, reader: reader, writer: writer, debug: true}
	line, _ = object.receive()

	log.Print(line)

	return object, nil
}

// Size 返回文件的大小。
func (ftp *FTP) Size(path string) (size int, err error) {
	line, err := ftp.cmd("213", "SIZE %s", path)

	if err != nil {
		return 0, err
	}

	return strconv.Atoi(line[4 : len(line)-2])
}
