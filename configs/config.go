package configs

// HostInfo 扫描地址及端口信息
type HostInfo struct {
	ScanHost    string              // 程序运行时扫描的地址
	ScanPort    string              // 程序运行时扫描的端口
	Hosts       []string            // 需要扫描的 IP 地址列表
	Ports       []string            // 需要扫描的端口号列表
	HostPortMap map[string][]string // 用于按照map的形式，存放最终扫描的端口号信息
	Url         string              // web扫描url
	UrlList     []string            // web服务扫描地址
	Infostr     []string            // web指纹信息列表
}

var HostPort []string // 临时存放ip:port形式的数组

// AllPorts 全端口号
var AllPorts = "1-65535"

// GeneralPorts 默认常见端口号
var GeneralPorts = "21,22,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,135,139,443,445,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1433,1521,1888,2008,2020,2100,2375,2379,3000,3008,3128,3306,5432,3505,5555,6379,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,11211,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,27017,28018,20880"

// CommandInfo 功能参数选择模块
type CommandInfo struct {
	Value   string // 待用参数值
	Modular string // 模块名称
}

// UserDict 用于爆破的用户名ID字典
var UserDict = map[string][]string{
	"ftp":      {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"ssh":      {"root", "admin"},
	"smb":      {"administrator", "admin", "guest"},
	"mssql":    {"sa", "sql"},
	"oracle":   {"sys", "systemapp", "admin", "test", "web", "orcl"},
	"mysql":    {"root", "mysql"},
	"rdp":      {"administrator", "admin", "guest"},
	"postgres": {"postgres", "admin"},
	"redis":    {"admin"},
	"elastic":  {"root", "elastic"},
	"mongodb":  {"root", "admin"},
	"snmp":     {"public", "privicy"},
}

// Passwords 用于爆破密码使用的密码列表
var Passwords = []string{"computer", "123456", "admin", "admin123", "root", "", "pass123", "pass@123", "password", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "systemapp", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "Charge123", "Aa123456789", "changeme"}

// PocInfo Poc扫描信息(Web)
type PocInfo struct {
	Target  string // 目标地址
	PocName string // Poc名称
}

// 常规定义参数
var (
	Ifms              bool     // 信息扫描判断
	Satt              bool     // 信息+漏洞扫描判断
	Apon              bool     // 开启精简端口号扫描
	LogLevel          int      // log等级,默认设置3级
	NoColor           bool     // 是否开启log输出非颜色版设置
	OutputFileName    string   // 用于设置log输出名称设置
	NoSave            bool     // not save file // logsync.go 中设置不进行日志写入的设置, 注：在常规的logger中并没有设置该参数
	NoProbe           bool     // 不进行主机存活扫描
	ThreadsPortScan   int      // 端口扫描线程 (default 1000)  -tps int
	PortFile          string   // 存放端口号的文件地址
	HostFile          string   // host file, -hf ip.txt
	Timeout           int64    // Set timeout, flag 中默认为 3
	NoScanModular     string   // 不进行扫描的模块名称
	NoScanModularList []string // 不进行扫描的模块名称list

)

// Web相关参数使用
var (
	URL         string   // web url
	UrlFile     string   // web url file
	Urls        []string // url 列表
	DnsLog      bool     // 使用 dnslog poc
	IsWebCan    bool     // 不进行web漏洞扫描
	PocFull     bool     // poc全部扫描使用，如：shiro 100 key
	WebTimeout  int      // 设置web超时,flag中默认为 5
	WebThread   int      // Web扫描相关线程
	PocNum      int      // -num poc扫描速率，flag中默认为20
	Proxy       string   // 设置 poc 代理, -proxy http://127.0.0.1:8080
	Socks5Proxy string   // 设置socks5代理参数
	Pocinfo     PocInfo  // POC扫描参数信息
	PocPath     string   // poc 路径
	Cookie      string   // web cookie
)

// 账号密码相关参数使用
var (
	Username string // 账号ID参数
	Password string // 密码列表
	Userfile string // 账号文件地址
	Passfile string // 密码文件地址
)

// 漏洞相关参数
var (
	SC string // ms17 shellcode,as -sc add
)
