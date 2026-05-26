// This program demonstrates using the sbomgen library to generate a CycloneDX SBOM.
//
// Usage:
//
//	go run examples/main.go [directory]
//
// If no directory is provided, it scans pkg/sbomgen/testdata which contains a
// sample Cargo.lock fixture.
package main

import (
	"fmt"
	"os"

	"github.com/DataDog/datadog-sbom-generator/pkg/sbomgen"
)

func main() {
	dir := "pkg/sbomgen/testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	result, err := sbomgen.GenerateSBOM([]string{dir}, sbomgen.DefaultOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(string(result))
}
