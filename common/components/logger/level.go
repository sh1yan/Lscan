package logger

type Level int

const (
	LevelFatal   Level = iota // 值 0
	LevelError                // 值 1
	LevelInfo                 // 值 2
	LevelWarning              // 值 3
	LevelDebug                // 值 4
	LevelVerbose              // 值 5
)
