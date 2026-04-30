package java

import (
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m BuildGradleMatcher) GetSourceFile(sourceFile lockfile.DepFile) (lockfile.DepFile, error) {
	// lockfile (default, groovy)
	sourcefile, err := sourceFile.Open(buildGradleFilename)
	if err != nil {
		// kotlin
		sourcefile, err = sourceFile.Open(buildGradleKtsFilename)
	}

	// gradle verification metadata (<rootdir>/gradle/verification-metadata.xml)
	relativePath := "../" + buildGradleFilename
	if err != nil {
		// groovy
		sourcefile, err = sourceFile.Open(relativePath)
	}
	if err != nil {
		// kotlin
		sourcefile, err = sourceFile.Open("../" + buildGradleKtsFilename)
	}

	return sourcefile, err
}

func (m BuildGradleMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	// First, try to match against the main build.gradle file
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	m.matchFileContent(content, sourceFile.Path(), packages)

	buildGradlePath := sourceFile.Path()
	projectRoot := filepath.Dir(buildGradlePath)

	// Find all build.gradle files in the project
	buildFiles, err := m.findAllBuildGradleFiles(projectRoot)
	if err != nil {
		return err
	}

	// Match packages against all build.gradle files
	for _, buildFile := range buildFiles {
		// Skip if this is the source file (already processed above).
		// This can happen when Match() is called with a build.gradle file directly
		// instead of a lockfile (e.g., gradle.lockfile or verification-metadata.xml)
		if buildFile == sourceFile.Path() {
			continue
		}

		buildFileDepFile, err := sourceFile.Open(buildFile)
		if err != nil {
			continue
		}

		fileContent, err := io.ReadAll(buildFileDepFile)
		buildFileDepFile.Close()
		if err != nil {
			continue
		}

		m.matchFileContent(fileContent, buildFile, packages)
	}

	return nil
}

// findAllBuildGradleFiles finds all build.gradle and build.gradle.kts files
// starting from the project root directory
func (m BuildGradleMatcher) findAllBuildGradleFiles(projectRoot string) ([]string, error) {
	var buildFiles []string

	err := filepath.WalkDir(projectRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories and common non-source directories
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "build" || name == "test" {
				return filepath.SkipDir
			}

			return nil
		}

		// Check if this is a build.gradle or build.gradle.kts file
		if d.Name() == buildGradleFilename || d.Name() == buildGradleKtsFilename {
			buildFiles = append(buildFiles, path)
		}

		return nil
	})

	return buildFiles, err
}

// matchFileContent matches packages against the content of a single build.gradle file
func (m BuildGradleMatcher) matchFileContent(content []byte, sourcePath string, packages []lockfile.PackageDetails) {
	lines := fileposition.BytesToLines(content)

	for index, line := range lines {
		lineNumber := index + 1
		for key, pkg := range packages {
			group, artifact, _ := strings.Cut(pkg.Name, ":")
			// TODO: what to do if, while using extended format, components are split in multiple lines?
			if strings.Contains(line, group) && strings.Contains(line, artifact) {
				// If we find the dependency in build.gradle, it's a direct dependency
				packages[key].IsDirect = true

				scope := m.extractScope(line)
				if len(scope) > 0 {
					packages[key].DepGroups = append(packages[key].DepGroups, scope)
				}

				if strings.Contains(line, pkg.Version) {
					startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
					endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

					packages[key].LocationRole = models.LocationRoleManifest
					packages[key].BlockLocation = models.FilePosition{
						Line:     models.Position{Start: lineNumber, End: lineNumber},
						Column:   models.Position{Start: startColumn, End: endColumn},
						Filename: sourcePath,
					}

					nameLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, artifact, lineNumber, "['\":]", "['\":]")
					if nameLocation != nil {
						nameLocation.Filename = sourcePath
						packages[key].NameLocation = nameLocation
					}

					versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, pkg.Version, lineNumber, "['\":]", "['\"]")
					if versionLocation != nil {
						versionLocation.Filename = sourcePath
						packages[key].VersionLocation = versionLocation
					}
				}
			}
		}
	}
}

/*
This is based on https://docs.gradle.org/current/userguide/dependency_configurations.html#sub:what-are-dependency-configurations
We extract a runtimeClasspath scope when we find a runtime only instruction because it will only appear as "testRuntimeClasspath" in the lockfile

This let us make the difference between a testRuntime dependency and a runtime only dependency
*/
func (m BuildGradleMatcher) extractScope(line string) string {
	var instruction string
	if strings.Contains(line, "(") {
		instruction = strings.TrimSpace(strings.Split(line, "(")[0])
	} else {
		instruction = strings.TrimSpace(strings.Fields(line)[0])
	}

	if instruction == "runtimeOnly" {
		return "runtimeClasspath"
	}

	return ""
}

var _ lockfile.Matcher = BuildGradleMatcher{}
