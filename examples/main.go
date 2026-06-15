// This program demonstrates using the sbomgen library to generate a CycloneDX SBOM
// and extract build file dependencies from it.
//
// Usage:
//
//	go run examples/main.go [directory]
//
// If no directory is provided, it scans pkg/sbomgen/testdata which contains a
// sample Cargo.lock fixture.
//
// The program prints the generated SBOM JSON, then lists all manifest build files
// found in the SBOM via GetBuildFileTrees.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/DataDog/datadog-sbom-generator/pkg/sbomgen"
)

func main() {
	dir := "pkg/sbomgen/testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	result, err := sbomgen.GenerateSBOM([]string{dir}, sbomgen.DefaultOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating SBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(string(result))

	// Extract build files from the generated SBOM.
	buildFiles := sbomgen.GetBuildFileTrees(result)

	fmt.Fprintf(os.Stderr, "\n--- Build Files (%d found) ---\n", len(buildFiles))
	if len(buildFiles) == 0 {
		fmt.Fprintln(os.Stderr, "(none)")
		return
	}

	// Sort for deterministic output.
	keys := make([]sbomgen.BuildFile, 0, len(buildFiles))
	for bf := range buildFiles {
		keys = append(keys, bf)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].FilePath != keys[j].FilePath {
			return keys[i].FilePath < keys[j].FilePath
		}
		return string(keys[i].FileType) < string(keys[j].FileType)
	})

	for _, bf := range keys {
		rels := buildFiles[bf]
		if bf.RepoPath != "" {
			fmt.Fprintf(os.Stderr, "  [%s] %s (repo: %s)\n", bf.FileType, bf.FilePath, bf.RepoPath)
		} else {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", bf.FileType, bf.FilePath)
		}
		if rels.ID != "" {
			fmt.Fprintf(os.Stderr, "    id: %s\n", rels.ID)
		}
		for _, dep := range rels.Dependencies {
			fmt.Fprintf(os.Stderr, "    dep (hop=%d): %s\n", dep.HopCount, dep.FilePath)
		}
	}
}
