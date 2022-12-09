package components

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Delete_extra_space 删除字符串中的多余空格，有多个空格时，仅保留一个空格
func Delete_extra_space(s string) string {
	// 原文链接：https://blog.csdn.net/weixin_41621706/article/details/84801586
	s1 := strings.Replace(s, "	", " ", -1)       //替换tab为空格
	regstr := "\\s{2,}"                          //两个及两个以上空格的正则表达式
	reg, _ := regexp.Compile(regstr)             //编译正则表达式
	s2 := make([]byte, len(s1))                  //定义字符数组切片
	copy(s2, s1)                                 //将字符串复制到切片
	spc_index := reg.FindStringIndex(string(s2)) //在字符串中搜索
	for len(spc_index) > 0 {                     //找到适配项
		s2 = append(s2[:spc_index[0]+1], s2[spc_index[1]:]...) //删除多余空格
		spc_index = reg.FindStringIndex(string(s2))            //继续在字符串中搜索
	}
	return string(s2)
}

// CreatShowSpaceOne 生成空格字符串，用于在部分需要换行显示的输出终使用,一级目录
func CreatShowSpaceOne() string {

	timelen := fmt.Sprintf("[%s]", time.Now().Format("2006.1.2"))

	var space string                   // 空格字符串
	var initial = 1                    // 默认最多值
	spaceint := initial + len(timelen) // 需要输出的空格数

	for i := 0; i < spaceint; i++ {
		space = space + " "
	}
	return space // 返回需要输出的空格
}

// CreatShowSpaceTwo  生成空格字符串，用于在部分需要换行显示的输出终使用,二级目录
func CreatShowSpaceTwo() string {

	timelen := fmt.Sprintf("[%s]", time.Now().Format("2006.1.2"))

	var space string                   // 空格字符串
	var initial = 5                    // 默认最多值
	spaceint := initial + len(timelen) // 需要输出的空格数

	for i := 0; i < spaceint; i++ {
		space = space + " "
	}
	return space // 返回需要输出的空格
}
