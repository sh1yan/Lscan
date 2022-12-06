# Lscan
一款内网快速打点的辅助性扫描工具，方便红队人员在内网横向移动前期的信息搜集、漏洞探测利用环节的工作开展。其工具特性主要为支持一键化三个档位的便捷式信息与漏洞扫描或每个功能模块单独批量式扫描探测功能。

注：工具源码中基本上所有关键点也有对应的注释，所以该工具项目也可作为一个golang编写内网信息扫描工具的入门级思路学习项目(有一点是需要吐槽的，随着功能不断的增加，逻辑的判断，越到后面代码阅读逻辑可能跳了2,3个函数，所以推荐使用goland来阅读学习)。

# 1. 背景介绍

22年7月份逐步发现github上大量的漏洞检测或攻击辅助性工具开始由Python编写转换为golang编写了，为了紧跟潮流趋势开始学习golang语言，俗话说想快速的学习一门编程语言那就是跟着项目走，我在熟悉完基础语法后就开始摸索跟着哪个项目走，最后选定了fscan工具，毕竟对内网渗透的知识还是很期待的，这样随着本项目工具的不断迭代，不但能加深golang语言的特性以及代码编写技巧，也能熟悉内网渗透的打点学习。

最后，需要感谢“代码参考链接”中的所有项目，让我学习了使用golang编写内网扫描工具的代码思路和部分语言特性逻辑，比如fscan中reflect.ValueOf()和[]reflect.Value{}的运用，嘿嘿。

# 2. 主要功能

| **信息收集：**                                               |
| :------------------------------------------------------------ |
| 主机存活扫描 / 端口扫描 / 端口服务识别 / WebTitle扫描 / Web指纹识别 |
| **口令爆破：**                                               |
| 数据库(mysql、mssql、redis、psql、oracle) / 应用服务(ssh、smb、rdp) |
| **漏洞扫描：**                                               |
| 系统漏洞() / Web漏洞()                                       |
| **深入功能：**                                               |
|                                                              |
| **外置插件：**                                               |
|                                                              |


# 3. 使用说明

常规用法：
``` 
Lscan.exe -h 192.168.1.1/24       (信息收集模式扫描)
Lscan.exe -h 192.168.1.1/24 -ifms (信息收集模式扫描)
Lscan.exe -h 192.168.1.1/24 -satt (扫描探测模式扫描)
Lscan.exe -h 192.168.1.1/24 -ffat (火力全开模式扫描)  // 非对外开放功能
```

其他用法：
```
Lscan.exe -h 192.168.1.1/24 -modular ftp -fun blast // 模块：ftp 功能：口令爆破
Lscan.exe -h 192.168.1.1/24 -m ftp -f blast // 模块：ftp 功能：口令爆破

Lscan.exe -h 192.168.1.1/24 -modular assets -fun survival // 模块：资产 功能：存活探测
Lscan.exe -h 192.168.1.1/24 -m assets -f survival // 模块：资产 功能：存活探测

Lscan.exe -h 192.168.1.1/24 -modular assets -fun port_open // 模块：资产 功能：端口开放扫描
Lscan.exe -h 192.168.1.1/24 -m assets -f port_open // 模块：资产 功能：端口开放扫描
```

参数列表：

```
说明：
        A类参数均可做单独使用参数，B类参数大部分需要结合C类参数使用，C类参数不可作为单独使用参数。

A类参数：
	-host string
	-h string
	目标ip: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12
	
	-ifms string
	参数介绍：只进行所有信息收集模块扫描
	
	-satt string
	参数介绍：信息收集模块 + 口令爆破模块 + 漏洞探测模块 = 开启扫描
	

B类参数：
	-modular string
	-m string
	模块选项： survival | portscan | ftp | rdp | smb | ssh | assets | mongodb | mssql | mysql | oracle | postgres | redis | webt | attack
	
			
辅助参数：

	-un string
	参数说明：指定某一个用户名，用于登录填充
	参数范围：ftp/rdp/smb/ssh/mongodb/mssql/mysql/oracle/postgres/redis

	-pw string
	参数说明：指定某一个密码，用于登录填充
	参数范围：ftp/rdp/smb/ssh/mongodb/mssql/mysql/oracle/postgres/redis

	-lpw G:mima/password.txt
	参数说明：用于加载本地的密码列表，进行爆破登录等用途
	参数范围：ftp/rdp/smb/ssh/mongodb/mssql/mysql/oracle/postgres/redis

	-port string
	-p
	参数说明：用于设置制定的端口，进行扫描爆破
	参数范围：


```

# 4. 运行展示
以下运行截图暂为Debug下运行截图,非正式公开版本(2022.11.27)  
`Lscan.exe -h 192.168.1.1-10  (默认信息收集模块)`
![](./image/debug-运行显示.png)

`Lscan.exe -h 192.168.1.1-10  (默认本地扫描结果输出)`
![](./image/debug-日志本地输出.png)

# 5. 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。
除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

# 6. Star Chart
[![Stargazers over time](https://starchart.cc/sh1yan/Lscan.svg)](https://starchart.cc/sh1yan/Lscan)



# 7. 工具部分逻辑须知

1、若自行flag中配备了socket5代理，其实只有以下功能中的流量是走的代理(工具自身设计没想设置代理的，等N个版本后再考虑全流量走吧)：PortCheck(单端口开放探测函数) / portscan / 135:findnet / 2181:zookeeper / 11211:memcached /


# 8. 代码参考(study)链接
https://github.com/shadow1ng/fscan  
https://github.com/JustinTimperio/gomap  
https://github.com/k8gege/LadonGo  
https://github.com/u21h2/nacs


# 9. 更新概况
[+] 2022/11/29 入口模式架构调整  
[+] 2022/11/27 项目框架、基础功能已初步完成  
[+] 2022/7/31 项目架构创建





 

