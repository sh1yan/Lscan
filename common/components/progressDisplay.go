package components

import (
	"Lscan/common/components/logger"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"os"
	"time"
)

func ProgressDisplay(totallength int, outtext string) (bar *progressbar.ProgressBar) {
	currentTime := time.Now().Format("2006.1.2")
	// [2022.12.8] [*] Wait for ssh password cracking...

	bar = progressbar.NewOptions(totallength,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription(fmt.Sprintf("[%s] [%s] %s ", logger.Cyan(currentTime), logger.LightGreen("*"), outtext)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
	return bar
}
