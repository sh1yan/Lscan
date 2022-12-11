package initlib

import (
	lcc "Lscan/common/components"
	"Lscan/common/components/logger"
	lc "Lscan/configs"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	keepAlive        = 15 * time.Second
	Client           *http.Client // 客户端连接
	ClientNoRedirect *http.Client // 客户端无重定向
)

func Inithttp() {
	err := InitHttpClient(lc.WebThread, time.Second*time.Duration(lc.WebTimeout))
	if err != nil {
		logger.Error(fmt.Sprint(err))
		os.Exit(1)
	}
}

func InitHttpClient(ThreadsNum int, Timeout time.Duration) error {
	d := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return lcc.WrapperTcpWithTimeout("tcp", addr, time.Second*time.Duration(lc.WebTimeout))
	}
	tr := &http.Transport{
		DialContext:         d,
		MaxConnsPerHost:     0,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: Timeout * 2,
		DisableKeepAlives:   false,
	}
	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout * 3,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout * 3,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}
