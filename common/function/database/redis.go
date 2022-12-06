package database

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/monnand/goredis"
	"net"
	"strconv"
)

func RedisAttack(info *lc.HostInfo) {
	ip := info.ScanHost
	port, _ := strconv.Atoi(info.ScanPort) // 端口号字符串转成 int
	if lcc.PortCheck(ip, port, "[REDIS]") {
		res1 := redisNullAuth(ip, port)
		if res1 {
			result := fmt.Sprintf("[REDIS] %s:%d Anonymous login succeeded! ", ip, port)
			logger.Success(result)
			return
		}
		for _, user := range lc.UserDict["redis"] {
			for _, pwd := range lc.Passwords {
				result := fmt.Sprintf("[REDIS] Check... " + ip + " " + user + " " + pwd)
				logger.Verbose(result)
				res := redisAuth(ip, user, pwd, port)
				if res == true {
					result := fmt.Sprintf("[REDIS] %s:%d Password cracked successfully! account number：%s password：%s ", ip, port, user, pwd)
					logger.Success(result)
					return
				}
			}
		}
		result := fmt.Sprintf("[REDIS] %s:%d Password cracking failed,The password security is high!", ip, port)
		logger.Failed(result)
	} else {
		result := fmt.Sprintf("[REDIS] %s:%d The service port is not open at present!", ip, port)
		logger.Warning(result)
	}
}

func redisNullAuth(host string, iport int) (result bool) {
	result = false
	var client goredis.Client
	port := strconv.Itoa(iport)
	client.Addr = host + ":" + port
	err := client.Set("test", []byte("ISOK"))
	if err != nil {
		//panic(err)
	}
	res, _ := client.Get("test")
	if string(res) == "ISOK" {
		result = true
	}
	client.Set("test", []byte("test"))
	return result
}

func redisAuth(ip, user, pwd string, port int) (result bool) {
	url := fmt.Sprintf("redis://%v:%v@%v:%v/", user, pwd, ip, port)
	opt, err := redis.ParseURL(url)
	if err != nil {
		fmt.Println(err)
		return false
	}
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return lcc.Getconn(addr, 0)
	}
	opt.Dialer = dialer
	rbd := redis.NewClient(opt)
	if rbd == nil {
		return false
	}
	_, err = rbd.Ping(context.Background()).Result()
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}
