package cores

import (
	lcfs "Lscan/common/function/systemapp"
	lc "Lscan/configs"
)

func InfoScan(addre *lc.HostInfo) {
	lcfs.IpSurvivalScan(addre)
	lcfs.PortScanTcp(addre)
	modualSelectScan("find-net", addre)
	modualSelectScan("webtitle", addre) // 执行webtitle扫描
}

func ScanAttack(addre *lc.HostInfo) {
	lcfs.IpSurvivalScan(addre)
	lcfs.PortScanTcp(addre)
	attackModualScan(addre)
}
