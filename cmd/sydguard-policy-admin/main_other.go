//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "managed policy admin is unsupported on this platform")
	os.Exit(1)
}
