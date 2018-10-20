package libknary

import (
	"fmt"

	"github.com/fatih/color"
)

// GiveHead makes pretty [+] things
func GiveHead(colour int) {
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	blue := color.New(color.FgBlue)
	white := color.New(color.FgWhite)

	switch colour {
	case 1: // success
		fmt.Printf("[")
		green.Printf("+")
		fmt.Printf("] ")
	case 2: // error
		fmt.Printf("[")
		red.Printf("+")
		fmt.Printf("] ")
	case 3: // debug
		fmt.Printf("[")
		blue.Printf("+")
		fmt.Printf("] ")
	default:
		fmt.Printf("[")
		white.Printf("+")
		fmt.Printf("] ")
	}
}

// Printy makes things print cool
func Printy(msg string, col int) {
	GiveHead(col)
	fmt.Println(msg)
}
