package orchestrator

import (
	"os"
	"strings"
)

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiBlack   = "\033[30m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
	ansiWhite   = "\033[37m"

	// 256-color codes for muted timestamp and narrator prefix.
	ansiGray     = "\033[38;5;245m"
	ansiMedGreen = "\033[38;5;34m"
)

var useColor = false

// IsTerminal reports whether f is attached to a character device.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// EnableColors opts the pretty logger into ANSI color output. Callers
// should only invoke this when the destination is a terminal and the
// user has not set NO_COLOR.
func EnableColors() {
	useColor = true
}

func styleAppend(sb *strings.Builder, code, s string) {
	if useColor {
		sb.WriteString(code)
		sb.WriteString(s)
		sb.WriteString(ansiReset)
	} else {
		sb.WriteString(s)
	}
}
