package infodict

import (
	lcc "Lscan/common/components"
	"crypto/md5"
	"fmt"
	"regexp"
)

// CheckDatas 检查数据类型
type CheckDatas struct {
	Body    []byte
	Headers string
}

// WebAppTypeCheck 判断http数据响应包中的内容，来检测该web应用框架名为哪个
func WebAppTypeCheck(CheckData []CheckDatas) []string {
	var matched bool      // 匹配结果
	var infoname []string // 存放匹配出来的信息名
	//遍历checkdata和rule
	for _, data := range CheckData { // 遍历需要输入检查的数据
		for _, rule := range RuleDatas { // 遍历web类型规则字典中的数据
			if rule.Type == "headers" {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers) // 判断 headers 关键字
			} else {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body)) // 判断非headers的其它类型的关键字，如：body、code、index、cookie等
			}
			if matched == true { // 如果匹配到了则进行复制对应的匹配到的应用名称
				infoname = append(infoname, rule.Name)
			}
		}
		flag, name := calcMd5(data.Body) // 使用md5关键词进行匹配
		if flag == true {
			infoname = append(infoname, name)
		}
	}

	infoname = lcc.RemoveDuplicate(infoname) // 结果去重

	if len(infoname) > 0 {
		return infoname
	}
	return nil
}

// calcMd5 计算md5
func calcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}
