package ui

import "github.com/fatih/color"

func Banner() {
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	println()
	println(red(`██████╗ ███████╗██████╗`), white(`     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗`))
	println(red(`██╔══██╗██╔════╝██╔══██╗`), white(`    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝`))
	println(red(`██████╔╝█████╗  ██████╔╝`), white(`    ██║     ███████║█████╗  ██║     █████╔╝`))
	println(red(`██╔══██╗██╔══╝  ██╔══██╗`), white(`    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗`))
	println(red(`██║  ██║███████╗██║  ██║`), white(`    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗`))
	println(red(`╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`), white(`     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝`))
	println()
	println(white("                      by Shunsuiky0raku"))
	println()
}
