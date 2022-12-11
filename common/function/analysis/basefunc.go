package analysis

import (
	lcfd "Lscan/common/function/database"
	lcfs "Lscan/common/function/systemapp"
	cve "Lscan/common/function/vuldict/cve"
	lcfw "Lscan/common/function/webapplication"
)

// FuncList 各类扫描模块函数名称和对应编号
var FuncList = map[string]interface{}{
	"survival":  lcfs.IpSurvivalScan,
	"portscan":  lcfs.PortScanTcp,
	"webtitle":  lcfw.WebTitle,
	"ftp":       lcfs.FtpAttack,
	"ssh":       lcfs.SshAttack,
	"find-net":  lcfs.Findnet,
	"snmp":      lcfs.SnmpAttack,
	"smb":       lcfs.SmbAttack,
	"ms17010":   cve.MS17010,
	"smbghost":  cve.SmbGhost,
	"rmi":       lcfs.RmiAttack,
	"mssql":     lcfd.MssqlAttack,
	"oracle":    lcfd.OracleAttack,
	"zookeeper": lcfs.ZookeeperAttack,
	"docker":    lcfs.DockerAttack,
	"mysql":     lcfd.MysqlAttack,
	"rdp":       lcfs.RdpAttack,
	"postgres":  lcfd.PostgresAttack,
	"redis":     lcfd.RedisAttack,
	"k8s":       lcfs.K8sAttack,
	"elastic":   lcfs.ElasticAttack,
	"memcached": lcfd.MemcachedAttack,
	"mongodb":   lcfd.MongodbAttack,
}

// PortForFunc 用于根据端口号转换对应的功能函数编号
var PortForFunc = map[string]string{
	"70001": "webtitle",
	"21":    "ftp",
	"22":    "ssh",
	"135":   "find-net",
	"161":   "snmp",
	"162":   "snmp",
	"445":   "smb,ms17010,smbghost",
	"1099":  "rmi",
	"1433":  "mssql",
	"1521":  "oracle",
	"2181":  "zookeeper",
	"2375":  "docker",
	"2379":  "k8s",
	"3306":  "mysql",
	"3389":  "rdp",
	"5432":  "postgres",
	"6379":  "redis",
	"6443":  "k8s",
	"9200":  "elastic",
	"10250": "k8s",
	"11211": "memcached",
	"27017": "mongodb",
}
