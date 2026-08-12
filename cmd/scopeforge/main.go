package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return 0
	}

	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return 0
	}

	fmt.Fprintf(stderr, "scopeforge: unknown command %q\n", args[0])
	printUsage(stderr)
	return 2
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: scopeforge <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  help       Show this help")
	fmt.Fprintln(output, "  version    Show the version")
}
