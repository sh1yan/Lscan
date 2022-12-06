package systemapp

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

// Findnet net信息扫描
func Findnet(info *lc.HostInfo) error {
	err := findnetScan(info)
	return err
}

// findnetScan 扫描135端口获取netinfo信息
func findnetScan(info *lc.HostInfo) error {
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	realhost := fmt.Sprintf("%s:%v", info.ScanHost, port)
	conn, err := lcc.WrapperTcpWithTimeout("tcp", realhost, time.Duration(lc.Timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return err
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(lc.Timeout) * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV1)
	if err != nil {
		return err
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}
	_, err = conn.Write(bufferV2)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return err
	}
	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return err
	}
	err = read(text, info.ScanHost)
	return err
}

// read 读取netinfo信息
func read(text []byte, host string) error {
	encodedStr := hex.EncodeToString(text)
	hostnames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostnames, "000000")
	result := "NetInfo:\n             [" + logger.LightGreen("*") + "] " + host
	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host, err := hex.DecodeString(hostname[i])
		if err != nil {
			return err
		}
		result += "\n                 [" + logger.LightGreen("->") + "] " + string(host)
	}
	logger.Success(result)
	return nil
}
