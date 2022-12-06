package components

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Icmp 使用 ip4:icmp 的形式，判断当前IP地址是否存在，该函数不适用并发使用
func Icmp(host string) (isok bool) {
	// Icmp(host string, Log *log.Logger)

	var size int      // 定义大小类型
	var timeout int64 // 定义输出时间
	var seq int16 = 1
	const ECHO_REQUEST_HEAD_LEN = 8 // 输出请求头部长度数

	size = 32     // 大小为32
	timeout = 200 // 输出时间100秒，这个速度特别快，并且测试结果也比较准确！

	starttime := time.Now() // 获取当前时间
	conn, err := net.DialTimeout("ip4:icmp", host, time.Duration(timeout*1000*1000))
	if err != nil {
		fmt.Println(err) //  若报错，则返回报错信息
		return
	}
	defer conn.Close() // 本函数运行结束后，关闭该连接端口

	id0, id1 := Genidentifier(host) // 通过获取host的两个uint8值，作为标识信息

	var msg []byte = make([]byte, size+ECHO_REQUEST_HEAD_LEN) // 创建一个数据包大小加请求头大小的比特数组
	msg[0] = 8                                                // echo
	msg[1] = 0                                                // code 0
	msg[2] = 0                                                // checksum
	msg[3] = 0                                                // checksum
	msg[4], msg[5] = id0, id1                                 //identifier[0] identifier[1]
	msg[6], msg[7] = Gensequence(seq)                         //sequence[0], sequence[1]

	length := size + ECHO_REQUEST_HEAD_LEN // 数据包大小整体长度数

	check := CheckSum(msg[0:length]) // 效验整体数据包
	msg[2] = byte(check >> 8)        // 数据包添加效验值
	msg[3] = byte(check & 255)       // 数据包添加效验值

	conn.SetDeadline(starttime.Add(time.Duration(timeout * 1000 * 1000))) // 设置超时状态
	_, err = conn.Write(msg[0:length])                                    // 在ip4:icmp隧道中发送刚才的数据包信息

	const ECHO_REPLY_HEAD_LEN = 20 // 输出应答包头部长度数

	var receive []byte = make([]byte, ECHO_REPLY_HEAD_LEN+length) // 创建一个数据应答包大小的比特数组
	n, err := conn.Read(receive)                                  // 在ip4:icmp隧道收取应答包大小的数据
	_ = n
	var endduration int = int(int64(time.Since(starttime)) / (1000 * 1000)) // 输出结束的时间

	if err != nil || receive[ECHO_REPLY_HEAD_LEN+4] != msg[4] || receive[ECHO_REPLY_HEAD_LEN+5] != msg[5] || receive[ECHO_REPLY_HEAD_LEN+6] != msg[6] || receive[ECHO_REPLY_HEAD_LEN+7] != msg[7] || endduration >= int(timeout) || receive[ECHO_REPLY_HEAD_LEN] == 11 {
		// 对整体结束的数据包进行效验，是否存在不一致的地方，若不一致，则无应该。
		// fmt.Println("ICMP: ", host, "：地址不可达！")
		return false
	} else {
		// fmt.Println("ICMP: ", host, "：地址存在！") // 若成功接受到发送的ICMP包数据，则输出该行数据。
		return true
	}
	return false
}

// CheckSum 效验整体数据包
func CheckSum(msg []byte) uint16 {
	sum := 0                           // sum 默认值为 0
	length := len(msg)                 // 获取比特数据的整体长度
	for i := 0; i < length-1; i += 2 { // 数据包长度每次循环减1，参数i每次循环加2
		sum += int(msg[i])*256 + int(msg[i+1]) // sum 的值，每次循环按照 int(msg[i])*256 + int(msg[i+1]) 规则进行相加
	}
	if length%2 == 1 { // 如果数据包长度 取2的余数就是1 ，则进入下面的公式进行相加
		sum += int(msg[length-1]) * 256 // notice here, why *256?
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var answer uint16 = uint16(^sum)
	return answer
}

// CheckError 效验错误数据
func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

// Gensequence 获取发送的顺序
func Gensequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

// Genidentifier 获取数据标识信息
func Genidentifier(host string) (byte, byte) {
	return host[0], host[1]
}

// Makemsg 构造ICMP数据包内容
func Makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := Genidentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = Gensequence(1)
	check := CheckSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

// Icmpalive 使用 ip4:icmp 的形式，判断当前IP地址是否存在，该函数适用于并发使用
func Icmpalive(host string) bool {
	startTime := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return false
	}
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}
	msg := Makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}
