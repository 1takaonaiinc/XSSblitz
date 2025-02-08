package banner

import (
	"fmt"
	"runtime"
	"strings"
)

const banner = `
██╗  ██╗███████╗███████╗██████╗ ██╗     ██╗████████╗███████╗
╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██║     ██║╚══██╔══╝╚══███╔╝
 ╚███╔╝ ███████╗███████╗██████╔╝██║     ██║   ██║     ███╔╝ 
 ██╔██╗ ╚════██║╚════██║██╔══██╗██║     ██║   ██║    ███╔╝  
██╔╝ ██╗███████║███████║██████╔╝███████╗██║   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
                                                              
    🔍 Advanced XSS Scanner with ML-powered Detection 🔍
           Version: 1.0.0
https://github.com/1takaonaiinc/xss-scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
━━━━━━━━━━━━━━━━━━━━━━━━━━━━`

// Windows-compatible color codes
const (
	colorReset  = "\033[0m"
	colorBlue   = "\033[94m"
	colorCyan   = "\033[96m"
	colorYellow = "\033[93m"
)

func init() {
	// Enable virtual terminal processing for Windows
	if runtime.GOOS == "windows" {
		fmt.Print("\033[?25l") // Hide cursor
	}
}

// Cleanup handles terminal cleanup on exit
func Cleanup() {
	if runtime.GOOS == "windows" {
		fmt.Print("\033[?25h")   // Show cursor
		fmt.Print("\033[0m")     // Reset all attributes
		fmt.Print("\033[?1049l") // Restore main screen buffer
	}
}

// Print displays the banner with color and version info
func Print() {
	if runtime.GOOS == "windows" {
		fmt.Print("\033[2J\033[H") // Clear screen and move to home position
	}

	// Split banner into lines
	lines := strings.Split(banner, "\n")

	// Process each line with appropriate color
	for i, line := range lines {
		switch {
		case i < 7: // Main ASCII art
			fmt.Println(colorBlue + line + colorReset)
		case i == 7: // Empty line
			fmt.Println(line)
		case i == 8: // Tagline
			fmt.Println(colorCyan + line + colorReset)
		case i == 9: // Version line - add Go version
			fmt.Printf(colorYellow+"           Version: 1.0.0 - Built with Go %s\n"+colorReset, runtime.Version())
		default:
			fmt.Println(colorBlue + line + colorReset)
		}
	}

	fmt.Print("\n") // Add some spacing
}
