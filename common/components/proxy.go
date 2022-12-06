package components

import (
	lc "Lscan/configs"
	"errors"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
	"time"
)

// WrapperTcpWithTimeout 带超时的 TCP 连接数据包，返回一个 net.Conn
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	// network ：协议
	// address ：ip 地址
	// timeout ：超时时间

	d := &net.Dialer{Timeout: timeout} // 设置超时时间，并生成带有超时的 net.Dialer
	return wrapperTCP(network, address, d)
}

// wrapperTCP TCP数据包连接，返回一个 net.Conn
func wrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	// get conn
	// forward 为携带超时时间的 net.Dialer

	var conn net.Conn
	if lc.Socks5Proxy == "" { // 判断是否开启代理，若未开启,则开始尝试 tcp 连接端口
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else { // 若开启Socks5Proxy,则开始使用代理进行尝试 tcp 连接端口
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil

}

// Socks5Dailer socks5代理连接函数
func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	// forward 为携带超时时间的 net.Dialer
	// 该函数需要结合着 WrapperTCP() 使用

	u, err := url.Parse(lc.Socks5Proxy) // 将字符串变更为 url.URL 类型
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" { // 对 Socks5Proxy 的 Scheme 进行强制变更为小写，去和 socks5 比较是否一致
		return nil, errors.New("Only support socks5")
	}
	address := u.Host
	var auth proxy.Auth
	var dailer proxy.Dialer
	if u.User.String() != "" { // 效验 Socks5Proxy 的用户名是否为空，若为空则进入到 else 流程内，调整认证参数为空
		auth = proxy.Auth{}
		auth.User = u.User.Username()    // 获取账号
		password, _ := u.User.Password() // 获取密码
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", address, &auth, forward) // 尝试 proxy.SOCKS5 连接 (带认证)
	} else {
		dailer, err = proxy.SOCKS5("tcp", address, nil, forward) // 尝试 proxy.SOCKS5 连接 (不带认证)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil // 返回连接成功的  proxy.Dialer
}
