package webapplication

import (
	"Lscan/common/components/logger"
	"Lscan/common/function/webapplication/infodict"
	lcfwi "Lscan/common/function/webapplication/initlib"
	lc "Lscan/configs"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	Charsets = []string{"utf-8", "gbk", "gb2312"} // 编码
	baseinfo httpresp                             // HTTP请求响应
)

// httpresp HTTP请求响应体
type httpresp struct {
	len   string
	title string
	code  int
}

// WebTitle flag 1 first try
// flag 2 /favicon.ico
// flag 3 302
// flag 4 400 -> https
// 根据协议设置url，进行第一次获取checkdata尝试，如果遇到跳转则跟进再次尝试，如果返回有https则重新设置url再次尝试以上步骤
func WebTitle(info *lc.HostInfo) (*lc.HostInfo, error) {
	var CheckData []infodict.CheckDatas // 生成一个检查类型
	defer func() {                      // 函数运行结束后，清空 info.url 的值
		info.Url = ""
	}()
	//设置url
	if info.Url == "" { // 若flag中url为空，则直接对info信息进行赋值
		if info.ScanPort == "80" {
			info.Url = fmt.Sprintf("http://%s", info.ScanHost)
		} else if info.ScanPort == "443" {
			info.Url = fmt.Sprintf("https://%s", info.ScanHost)
		} else {
			host := fmt.Sprintf("%s:%s", info.ScanHost, info.ScanPort)
			protocol := GetProtocol(host, time.Duration(lc.WebTimeout)*time.Second) // 获取当前 ip:port 协议
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.ScanHost, info.ScanPort)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			protocol := GetProtocol(info.Url, time.Duration(lc.WebTimeout)*time.Second)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}
	// re正则匹配返回跳转的url或者https，checkdata是header和body
	err, result, CheckData, _ := geturl(info, 1, CheckData)
	logger.Debug("首次请求 get url 地址完成")
	logger.Debug(fmt.Sprint("首次URL地址:", info.Url, " = Jump-URL-Address => ", result))
	firstInfoUrl := info.Url // 首次输入url地址，用于结果输出时判断是否跳转
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return nil, err
	}

	// 判断是否有跳转,如果有跳转，跟进跳到头，增加一次的CheckData
	if strings.Contains(result, "://") {
		redirecturl, err := url.Parse(result)
		if err == nil {
			info.Url = redirecturl.String()
			err, result, CheckData, _ = geturl(info, 3, CheckData)
			if err != nil {
				return nil, err
			}
		}
	}
	// 判断返回如果是https
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData, _ = geturl(info, 1, CheckData)
		if strings.Contains(result, "://") {
			// 有跳转
			redirecturl, err := url.Parse(result)
			if err == nil {
				info.Url = redirecturl.String()
				err, result, CheckData, _ = geturl(info, 3, CheckData)
				if err != nil {
					return nil, err
				}
			}
		} else {
			if err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}

	err, _, CheckData, baseinfo = geturl(info, 2, CheckData)
	if err != nil {
		return nil, err
	}
	// 将CheckData送去与指纹库对比
	info.Infostr = infodict.WebAppTypeCheck(CheckData)
	logger.Debug(fmt.Sprint("当前web指纹判别结果: ", info.Infostr)) // -------------------------------测试代码

	// 吐槽下，暂时没想好杂优化以下代码 2022.12.11
	if info.Url == firstInfoUrl { // 判断是否存在跳转的情况，不存在跳转进入下列

		if info.Infostr != nil {
			logger.Success(fmt.Sprintf("WebUrl: %v \t code:%v \t len:%v \t title:%v \t banner:%s", info.Url, baseinfo.code, baseinfo.len, baseinfo.title, info.Infostr))
		} else {
			// [+] WebUrl: http://192.168.1.1/cgi-bin/index2.asp  code:200 len:13532 title:Login
			logger.Success(fmt.Sprintf("WebUrl: %v \tcode:%v \t len:%v \t title:%v", info.Url, baseinfo.code, baseinfo.len, baseinfo.title))
		}

	} else { // 存在URL跳转的行为

		if info.Infostr != nil {
			logger.Success(fmt.Sprintf("WebUrl: %v \t code:%v \t len:%v \t title:%v \t banner:%s \t SourceURL:%s", info.Url, baseinfo.code, baseinfo.len, baseinfo.title, info.Infostr, firstInfoUrl))
		} else {
			// [+] WebUrl: http://192.168.1.1/cgi-bin/index2.asp  code:200 len:13532 title:Login
			logger.Success(fmt.Sprintf("WebUrl: %v \tcode:%v \t len:%v \t title:%v \t SourceURL:%s", info.Url, baseinfo.code, baseinfo.len, baseinfo.title, firstInfoUrl))
		}

	}

	return info, err
}

// 获取http协议类型
func GetProtocol(host string, Timeout time.Duration) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: Timeout}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	protocol := "http"
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}

// flag 1 first try
// flag 2 /favicon.ico
// flag 3 302
// flag 4 400 -> https
// geturl 获取url信息
func geturl(info *lc.HostInfo, flag int, CheckData []infodict.CheckDatas) (error, string, []infodict.CheckDatas, httpresp) {
	Url := info.Url
	logger.Debug(fmt.Sprint("输入URL地址: ", Url))
	// 设置url：访问到网站的图标
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}

	req, err := http.NewRequest("GET", Url, nil) // 生成一个 request
	if err == nil {
		// 设置http请求头
		req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Cookie", "rememberMe=1") // 增加shiro 判断
		req.Header.Set("Connection", "close")
		var client *http.Client
		if flag == 1 {
			client = lcfwi.ClientNoRedirect // 设置客户端无重定向的client
		} else {
			client = lcfwi.Client // 设置普通客户端连接
		}
		logger.Debug(fmt.Sprint("请求URL连接: ", req.URL))
		// 发送请求
		resp, err := client.Do(req)
		logger.Debug(fmt.Sprint("获取当前请求响应信息: ", resp))
		if err == nil {
			defer resp.Body.Close()
			var title string
			var text []byte
			body, err := getRespBody(resp) // 获取响应正文
			if err != nil {
				logger.DebugError(err) // ------------------------------ 测试代码
				return err, "https", CheckData, baseinfo
			}
			// 获取http title
			if flag != 2 {
				// 获取title
				re := regexp.MustCompile("(?ims)<title.*>(.*)</title>")
				find := re.FindSubmatch(body)
				// logger.Debug(fmt.Sprint("已匹配到当前Title信息: ", string(find[0]))) // 这里存在一个bug，find[0]这个若没匹配到，则会系统报错
				if len(find) > 1 {
					text = find[1]
					GetEncoding := func() string { // 判断Content-Type
						r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
						if err != nil {
							return ""
						}
						headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
						if headerCharset != "" {
							for _, v := range Charsets { // headers 编码优先，所以放在前面
								if strings.Contains(strings.ToLower(headerCharset), v) == true {
									return v
								}
							}
						}

						r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
						if err != nil {
							return ""
						}
						htmlCharset := r2.FindString(string(body))
						if htmlCharset != "" {
							for _, v := range Charsets {
								if strings.Contains(strings.ToLower(htmlCharset), v) == true {
									return v
								}
							}
						}
						return ""
					}
					encode := GetEncoding()
					var encode2 string
					detector := chardet.NewTextDetector()
					detectorstr, _ := detector.DetectBest(body)
					if detectorstr != nil {
						encode2 = detectorstr.Charset
					}
					if encode == "gbk" || encode == "gb2312" || strings.Contains(strings.ToLower(encode2), "gb") {
						titleGBK, err := Decodegbk(text)
						if err == nil {
							title = string(titleGBK)
						}
					} else {
						title = string(text)
					}
				} else {
					title = ""
				}
				title = strings.Trim(title, "\r\n \t")
				title = strings.Replace(title, "\n", "", -1)
				title = strings.Replace(title, "\r", "", -1)
				title = strings.Replace(title, "&nbsp;", " ", -1)
				if len(title) > 100 {
					title = title[:100]
				}
				if title == "" {
					title = ""
				}
				length := resp.Header.Get("Content-Length")
				if length == "" {
					length = fmt.Sprintf("%v", len(body))
				}

				baseinfo = httpresp{title: title, code: resp.StatusCode, len: length}
				logger.Debug(fmt.Sprint("baseinfo: httpresp", baseinfo))
			}
			CheckData = append(CheckData, infodict.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
			redirURL, err1 := resp.Location()
			if err1 == nil {
				return nil, redirURL.String(), CheckData, baseinfo
			}
			if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
				return err, "https", CheckData, baseinfo
			}
			return nil, "", CheckData, baseinfo
		}
		return err, "https", CheckData, baseinfo
	}
	return err, "", CheckData, baseinfo
}

// 获取响应body
func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

// Decodegbk 解码GBK
func Decodegbk(s []byte) ([]byte, error) { // GBK解码
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}
