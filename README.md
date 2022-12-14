# Lscan
一款内网快速打点的辅助性扫描工具，方便红队人员在内网横向移动前期的信息搜集、漏洞探测利用环节的工作开展。其工具特性主要为支持一键化三个档位的便捷式信息与漏洞扫描或每个功能模块单独批量式扫描探测功能(第三档位计划是增加getshell功能，等后续迭代吧)。

注：工具源码中基本上所有关键点都有对应的注释，所以该工具项目也可作为一个golang编写内网信息扫描工具的入门级思路学习项目(有一点是需要吐槽的，随着功能不断的增加，逻辑的判断，越到后面代码阅读逻辑可能跳了2,3个函数，所以推荐使用goland来阅读学习)。

# 1. 背景介绍

22年7月份逐步发现github上大量的漏洞检测或攻击辅助性工具开始由Python编写转换为golang编写了，为了紧跟潮流趋势开始学习golang语言，俗话说想快速的学习一门编程语言那就是跟着项目走，我在熟悉完基础语法后就开始摸索跟着哪个项目走，最后选定了fscan工具，毕竟对内网渗透的知识还是很期待的，这样随着本项目工具的不断迭代，不但能加深golang语言的特性以及代码编写技巧，也能熟悉内网渗透的打点学习。

最后，需要感谢“代码参考链接”中的所有项目，让我学习了使用golang编写内网扫描工具的代码思路和部分语言特性逻辑，比如fscan中reflect.ValueOf()和[]reflect.Value{}的运用，嘿嘿。

# 2. 主要功能

| **信息收集：**                                                               |
|:------------------------------------------------------------------------|
| 主机存活扫描 / 端口扫描 / 端口服务识别 / WebTitle扫描 / Web指纹识别 / find-net / NetBios      |
| **口令爆破：**                                                               |
| mysql、mssql、redis、psql、oracle、memcached、mongodb、ssh、smb、rdp、ftp、elastic |
| **漏洞扫描：**                                                               |
| docker、kubernetes、rmi、snmp、zookeeper、MS17010、MS-SMB2                    |
| **扩展功能：**                                                               |
|                                                                         |



# 3. 使用说明

常规用法：
``` 
Lscan.exe -h 192.168.1.1/24       (信息收集模式扫描)
Lscan.exe -h 192.168.1.1/24 -ifms (信息收集模式扫描)
Lscan.exe -h 192.168.1.1/24 -satt (扫描探测模式扫描)
```

其他用法：
```
Lscan.exe -h 192.168.1.1/24 -m ftp      // 对C段进行批量ftp段爆破扫描
Lscan.exe -h 192.168.1.1/24 -m survival // 对C段进行存活探测扫描
Lscan.exe -h 192.168.1.1/24 -m portscan // 对C段进行端口开放扫描
Lscan.exe -h 192.168.1.1/24 -satt -nm ssh // 对C段进行扫描探测模式扫描,但不进行ssh口令爆破
Lscan.exe -h 192.168.1.1/24 -satt -apon // 对C段进行扫描探测模式扫描,端口进行全端口扫描
Lscan.exe -h 192.168.1.1/24 -satt -np // 对C段进行扫描探测模式扫描,但不进行主机存活性探测
Lscan.exe -h 192.168.1.1 -satt -logl 4 // 对主机ip进行扫描探测,同时在命令行中输出Debug信息
Lscan.exe -h 192.168.1.1 -satt -logl 5 // 对主机ip进行扫描探测,同时在命令行中输出Debug信息和其他详细扫描显示信息
```

参数列表：

```
  -host string
        设置扫描的主机的IP地址,例如: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2
  -hf string
        输入需要扫描的主机ip文件路径和名称,例如: -hf ip.txt
  -h string
        设置扫描的主机的IP地址,例如: 192.168.1.1 | 192.168.1.1-255 | 192.168.1.1,192.168.1.2
  -pf string
        输入需要扫描的ip端口文件路径和名称,例如: -pf port.txt
  -p string
        设置扫描的IP端口列表,例如: 22 | 1-65535 | 22,80,3306
  -ifms
        启动信息收集模式扫描
  -satt
        启动扫描探测模式扫描
  -m string
        选择需要单独扫描的模块功能: survival | portscan | ftp | ssh | find-net | snmp | smb | ms17010 | smbghost | rmi | mssql | oracle | zookeeper | docker | mysql | rdp | postgres | redis | webtitle | k8s | elastic | memcached | mongodb | netbios
  -apon
        启用此设置将使用对1~65535端口号列表进行扫描
  -np
        设置不进行主机存活性扫描
  -nm string
        设置不扫描的模块名称,例如 -nm ssh ,因为该模块功能爆破速度较慢,设置速度快的话会导致爆破结果不准确
  -o string
         设置扫描结果的输出路径和结果名称 (默认名 outcome.txt)
  -userf string
        输入设置口令爆破时所需的账号文件路径和名称,例如: -userf user.txt
  -user string
        设置口令爆破时的账号
  -pwdf string
        输入设置口令爆破时所需的密码文件路径和名称,例如: -pwdf pwd.txt
  -pwd string
        设置口令爆破时的密码
  -logl int
        设置 log 等级,用于判断日志级别输出 (默认等级 3,最高等级可设置为 5)
  -socks5 string
        设置socks5代理，将在tcp连接中使用，超时设置将不起作用,例如: -socks5  socks5://127.0.0.1:1080
  -tps int
        设置端口扫描模块功能的并发线程值 (默认值 1000)
  -time int
        设置tcp连接超时时间 (默认值 3)
	
```

# 4. 运行展示
以下运行截图均为代码Debug测试中运行截图,非最终结果样式(2022.12.12)  
`Lscan.exe -h 10.171.130.99  (默认信息收集模块)`
![](./image/默认运行显示.png)

`Lscan.exe -h 10.171.130.99  (默认本地扫描结果输出)`
![](./image/查看本地日志输出结果.png)

`Lscan.exe -h 10.171.130.99 -satt  (扫描探测模块)`
![](./image/satt攻击运行显示.png)

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
https://github.com/zyylhn/zscan  


# 9. 更新概况
[+] 2022/12/08 调整ssh功能模块,增加扫描进度条显示  
[+] 2022/11/29 入口模式架构调整  
[+] 2022/11/27 项目框架、基础功能已初步完成  
[+] 2022/7/31 项目架构创建





 

