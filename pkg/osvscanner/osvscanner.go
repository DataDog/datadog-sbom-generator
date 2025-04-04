package osvscanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog/datadog-sbom-generator/internal/customgitignore"
	"github.com/datadog/datadog-sbom-generator/internal/utility/fileposition"

	"github.com/datadog/datadog-sbom-generator/internal/output"
	"github.com/datadog/datadog-sbom-generator/pkg/lockfile"
	"github.com/datadog/datadog-sbom-generator/pkg/models"
	"github.com/datadog/datadog-sbom-generator/pkg/reporter"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

type ScannerActions struct {
	DirectoryPaths []string
	Recursive      bool
	NoIgnore       bool
	Debug          bool
	EnableParsers  []string
}

// NoPackagesFoundErr for when no packages are found during a scan.
//
//nolint:errname,stylecheck // Would require version major bump to change
var NoPackagesFoundErr = errors.New("no packages found in scan")

// VulnerabilitiesFoundErr includes both vulnerabilities being found or license violations being found,
// however, will not be raised if only uncalled vulnerabilities are found.
//
//nolint:errname,stylecheck // Would require version major bump to change
var VulnerabilitiesFoundErr = errors.New("vulnerabilities found")

// ErrAPIFailed describes errors related to querying API endpoints.
var ErrAPIFailed = errors.New("API query failed")

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
func scanDir(r reporter.Reporter, dir string, recursive bool, useGitIgnore bool, enabledParsers map[string]bool) ([]lockfile.PackageDetails, []models.ScannedArtifact, error) {
	var ignoreMatcher *gitIgnoreMatcher
	if useGitIgnore {
		var err error
		ignoreMatcher, err = parseGitIgnores(dir, recursive)
		if err != nil {
			r.Errorf("Unable to parse git ignores: %v\n", err)
			useGitIgnore = false
		}
	}

	root := true

	var scannedPackages []lockfile.PackageDetails
	var scannedArtifacts []models.ScannedArtifact

	return scannedPackages, scannedArtifacts, filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			r.Infof("Failed to walk %s: %v\n", path, err)
			return err
		}

		path, err = filepath.Abs(path)
		if err != nil {
			r.Errorf("Failed to walk path %s\n", err)
			return err
		}

		if useGitIgnore {
			match, err := ignoreMatcher.match(path, info.IsDir())
			if err != nil {
				r.Infof("Failed to resolve gitignore for %s: %v\n", path, err)
				// Don't skip if we can't parse now - potentially noisy for directories with lots of items
			} else if match {
				if root { // Don't silently skip if the argument file was ignored.
					r.Errorf("%s was not scanned because it is excluded by a .gitignore file. Use --no-ignore to scan it.\n", path)
				}
				if info.IsDir() {
					return filepath.SkipDir
				}

				return nil
			}
		}

		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if extractor, _ := lockfile.FindExtractor(path, "", enabledParsers); extractor != nil {
				pkgs, artifact, err := scanLockfile(r, path, "", enabledParsers)
				if err != nil {
					r.Warnf("Attempted to scan lockfile but failed: %s (%v)\n", path, err.Error())
				}
				scannedPackages = append(scannedPackages, pkgs...)
				if artifact != nil {
					scannedArtifacts = append(scannedArtifacts, *artifact)
				}
			}
		}

		if !root && !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		root = false

		return nil
	})
}

type gitIgnoreMatcher struct {
	matcher  gitignore.Matcher
	repoPath string
}

func parseGitIgnores(path string, recursive bool) (*gitIgnoreMatcher, error) {
	patterns, repoRootPath, err := customgitignore.ParseGitIgnores(path, recursive)
	if err != nil {
		return nil, err
	}

	matcher := gitignore.NewMatcher(patterns)

	return &gitIgnoreMatcher{matcher: matcher, repoPath: repoRootPath}, nil
}

// gitIgnoreMatcher.match will return true if the file/directory matches a gitignore entry
// i.e. true if it should be ignored
func (m *gitIgnoreMatcher) match(absPath string, isDir bool) (bool, error) {
	pathInGit, err := filepath.Rel(m.repoPath, absPath)
	if err != nil {
		return false, err
	}
	// must prepend "." to paths because of how gitignore.ReadPatterns interprets paths
	pathInGitSep := []string{"."}
	if pathInGit != "." { // don't make the path "./."
		pathInGitSep = append(pathInGitSep, strings.Split(pathInGit, string(filepath.Separator))...)
	}

	return m.matcher.Match(pathInGitSep, isDir), nil
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r reporter.Reporter, path string, parseAs string, enabledParsers map[string]bool) (lockfile.Packages, *models.ScannedArtifact, error) {
	var err error
	var parsedLockfile lockfile.Lockfile

	f, err := lockfile.OpenLocalDepFile(path)

	if err == nil {
		// special case for the APK and DPKG parsers because they have a very generic name while
		// living at a specific location, so they are not included in the map of parsers
		// used by lockfile.Parse to avoid false-positives when scanning projects
		switch parseAs {
		case "apk-installed":
			parsedLockfile, err = lockfile.FromApkInstalled(path)
		case "dpkg-status":
			parsedLockfile, err = lockfile.FromDpkgStatus(path)
		case "osv-scanner":
			parsedLockfile, err = lockfile.FromOSVScannerResults(path)
		default:
			parsedLockfile, err = lockfile.ExtractDeps(f, parseAs, enabledParsers)
			// We are disabling this as we don't want to go through deps.dev to detect packages
			// if !compareOffline && (parseAs == "pom.xml" || filepath.Base(path) == "pom.xml") {
			//	parsedLockfile, err = extractMavenDeps(f)
			// } else {
			//	parsedLockfile, err = lockfile.ExtractDeps(f, parseAs, enabledParsers)
			// }
		}
	}

	if err != nil {
		return nil, nil, err
	}

	parsedAsComment := ""

	if parseAs != "" {
		parsedAsComment = fmt.Sprintf("as a %s ", parseAs)
	}

	r.Infof(
		"Scanned %s file %sand found %d %s\n",
		path,
		parsedAsComment,
		len(parsedLockfile.Packages),
		output.Form(len(parsedLockfile.Packages), "package", "packages"),
	)

	for i := range parsedLockfile.Packages {
		parsedLockfile.Packages[i].Source = models.SourceInfo{
			Path: path,
		}
	}

	return parsedLockfile.Packages, parsedLockfile.Artifact, nil
}

func initializeEnabledParsers(enabledParsers []string) map[string]bool {
	result := make(map[string]bool)

	if len(enabledParsers) == 0 {
		// If the list is empty, it means the flag is not set on the CLI, everything should be enabled
		for _, parser := range lockfile.ListExtractors() {
			result[parser] = true
		}
	} else {
		for _, parser := range enabledParsers {
			result[parser] = true
		}
	}

	return result
}

// Perform osv scanner action, with optional reporter to output information
func DoScan(actions ScannerActions, r reporter.Reporter) (models.VulnerabilityResults, error) {
	enabledParsers := initializeEnabledParsers(actions.EnableParsers)

	if r == nil {
		r = &reporter.VoidReporter{}
	}

	var scannedPackages []lockfile.PackageDetails
	var scannedArtifacts []models.ScannedArtifact

	if actions.Debug {
		os.Setenv("debug", "true")
	}

	for _, dir := range actions.DirectoryPaths {
		r.Infof("Scanning dir %s\n", dir)
		pkgs, artifacts, err := scanDir(r, dir, actions.Recursive, !actions.NoIgnore, enabledParsers)
		if err != nil {
			return models.VulnerabilityResults{}, err
		}

		// Transforming any path into a relative path to the scanned directory path
		for index, pkg := range pkgs {
			pkgs[index].Source.Path = fileposition.ToRelativePath(dir, pkg.Source.Path)
			pkgs[index].BlockLocation.Filename = fileposition.ToRelativePath(dir, pkg.BlockLocation.Filename)

			if pkgs[index].NameLocation != nil {
				pkgs[index].NameLocation.Filename = fileposition.ToRelativePath(dir, pkg.NameLocation.Filename)
			}

			if pkgs[index].VersionLocation != nil {
				pkgs[index].VersionLocation.Filename = fileposition.ToRelativePath(dir, pkg.VersionLocation.Filename)
			}
		}
		for index, artifact := range artifacts {
			artifacts[index].Filename = fileposition.ToRelativePath(dir, artifact.Filename)
			if artifact.DependsOn != nil {
				artifacts[index].DependsOn.Filename = fileposition.ToRelativePath(dir, artifact.DependsOn.Filename)
			}
		}
		scannedPackages = append(scannedPackages, pkgs...)
		scannedArtifacts = append(scannedArtifacts, artifacts...)
	}

	if len(scannedPackages) == 0 {
		return models.VulnerabilityResults{}, NoPackagesFoundErr
	}

	vulnerabilityResults := groupBySource(r, scannedPackages, scannedArtifacts)

	return vulnerabilityResults, nil
}
