package ruby

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// This function returns whether or not the given line section is a source section.
func (parser *gemfileLockfileParser) isSourceSection(line string) bool {
	if strings.Contains(line, lockfileSectionDEPENDENCIES) {
		parser.isInDepSection = true
		return true
	}

	if strings.Contains(line, lockfileSectionGIT) ||
		strings.Contains(line, lockfileSectionGEM) ||
		strings.Contains(line, lockfileSectionPATH) ||
		strings.Contains(line, lockfileSectionPLUGIN) {
		parser.isInDepSection = false
		return true
	}

	return false
}

func (parser *gemfileLockfileParser) addDependency(name string, version string) {
	blockLocation := models.FilePosition{
		Line:     models.Position{Start: parser.lineNumber, End: parser.lineNumber},
		Column:   models.Position{Start: 1, End: len(parser.currentLine) + 1},
		Filename: parser.sourceFile,
	}

	if !parser.isInDepSection {
		parser.dependencies = append(parser.dependencies, extractor.PackageDetails{
			Name:           name,
			Version:        version,
			PackageManager: gemfilePackageManager,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         parser.currentGemCommit,
			BlockLocation:  blockLocation,
			LocationRole:   models.LocationRoleLockfile,
		})

		return
	}

	// find the package that exists already from parsing the `GEM` section
	// if not found, add it as a direct dep if found just set it as a direct dep
	found := false
	for i, dep := range parser.dependencies {
		if dep.Name == name {
			parser.dependencies[i].IsDirect = true
			found = true

			break
		}
	}

	if !found {
		parser.dependencies = append(parser.dependencies, extractor.PackageDetails{
			Name:           name,
			Version:        version,
			PackageManager: gemfilePackageManager,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         parser.currentGemCommit,
			IsDirect:       true,
			BlockLocation:  blockLocation,
			LocationRole:   models.LocationRoleLockfile,
		})
	}
}

func (parser *gemfileLockfileParser) parseSpec(line string) {
	// nameVersionReg := cachedregexp.MustCompile(`^( {2}| {4}| {6})(?! )(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)
	nameVersionReg := cachedregexp.MustCompile(`^( +)(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)

	results := nameVersionReg.FindStringSubmatch(line)

	if results == nil {
		return
	}

	spaces := results[1]

	if spaces == "" {
		log.Fatal("Weird error when parsing spec in Gemfile.lock (unexpectedly had no spaces) - please report this")
	}

	if len(spaces) == 4 || (len(spaces) == 2 && parser.isInDepSection) {
		parser.addDependency(results[2], results[3])
	}
}

func (parser *gemfileLockfileParser) parseSource(line string) {
	if line == "  specs" {
		// todo: skip for now
		return
	}

	// OPTIONS      = /^  ([a-z]+): (.*)$/i.freeze
	optionsRegexp := cachedregexp.MustCompile(`(?i)^ {2}([a-z]+): (.*)$`)

	// todo: support
	options := optionsRegexp.FindStringSubmatch(line)

	if options != nil {
		commit := strings.TrimPrefix(options[0], "  revision: ")

		// if the prefix was removed then the gem being parsed is git based, so
		// we store the commit to be included later
		if commit != options[0] {
			parser.currentGemCommit = commit
		}

		return
	}

	// todo: source check

	parser.parseSpec(line)
}

func isNotIndented(line string) bool {
	re := cachedregexp.MustCompile(`^\S`)

	return re.MatchString(line)
}

func (parser *gemfileLockfileParser) parseLineBasedOnState(line string) {
	switch parser.state {
	case parserStatePlatform:
		break
	case parserStateRuby:
		parser.rubyVersion = strings.TrimSpace(line)
	case parserStateBundledWith:
		parser.bundlerVersion = strings.TrimSpace(line)
	case parserStateDependency:
	case parserStateSource:
		parser.parseSource(line)
	default:
		log.Fatalf("Unknown supported '%s'\n", parser.state)
	}
}

func (parser *gemfileLockfileParser) parse(line string) {
	if parser.isSourceSection(line) {
		// clear the stateful package details,
		// since we're now parsing a new group
		parser.currentGemCommit = ""
		parser.state = parserStateSource
		parser.parseSource(line)

		return
	}

	switch line {
	case lockfileSectionDEPENDENCIES:
		parser.state = parserStateDependency
	case lockfileSectionPLATFORMS:
		parser.state = parserStatePlatform
	case lockfileSectionRUBY:
		parser.state = parserStateRuby
	case lockfileSectionBUNDLED:
		parser.state = parserStateBundledWith
	default:
		if isNotIndented(line) {
			parser.state = ""
		}

		if parser.state != "" {
			parser.parseLineBasedOnState(line)
		}
	}
}

func (e GemfileLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.BundlerFilePath.String()
}

func (e GemfileLockExtractor) IsOfficiallySupported() bool {
	return gemfileOfficiallySupported
}

func (e GemfileLockExtractor) PackageManager() models.PackageManager {
	return gemfilePackageManager
}

func (e GemfileLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parser gemfileLockfileParser
	parser.sourceFile = f.Path()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		parser.lineNumber++
		line := scanner.Text()
		parser.currentLine = line
		parser.parse(line)
	}

	if err := scanner.Err(); err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return parser.dependencies, nil
}

// Compile-time check: GemfileLockExtractor implements ArtifactExtractor.
var _ extractor.ArtifactExtractor = GemfileLockExtractor{}

func (e GemfileLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	gemfileDir := filepath.Dir(f.Path())
	gemfilePath := filepath.Join(gemfileDir, gemfileFilename)

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:  gemfilePath,
			Ecosystem: models.EcosystemRubyGems,
		},
	}

	gemfile, err := extractor.OpenLocalDepFile(gemfilePath)
	if err != nil {
		// No adjacent Gemfile — return bare artifact
		return artifact, nil
	}
	defer gemfile.Close()

	treeResult, err := extractor.ParseFile(gemfile, extractor.Ruby)
	if err != nil {
		return artifact, nil
	}
	defer treeResult.Close()

	pathValues, err := findGemsWithPath(treeResult.Node)
	if err != nil {
		return artifact, nil
	}

	seen := make(map[string]struct{})

	for _, pathVal := range pathValues {
		var targetDir string
		if filepath.IsAbs(pathVal) {
			targetDir = pathVal
		} else {
			targetDir = filepath.Join(gemfileDir, pathVal)
		}
		targetGemfile := filepath.Clean(filepath.Join(targetDir, gemfileFilename))

		if _, err := os.Stat(targetGemfile); err != nil {
			continue
		}

		// Skip targets outside the scan root
		if ctx.RootDir != "" {
			absRoot, err := filepath.Abs(ctx.RootDir)
			if err == nil {
				rel, err := filepath.Rel(absRoot, targetGemfile)
				if err != nil || strings.HasPrefix(rel, "..") {
					continue
				}
			}
		}

		if _, ok := seen[targetGemfile]; ok {
			continue
		}
		seen[targetGemfile] = struct{}{}

		artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
			Filename: targetGemfile,
		})
	}

	return artifact, nil
}

var GemfileExtractor = GemfileLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{
		&GemfileMatcher{},
		&GemspecFileMatcher{},
	}},
}

func ParseGemfileLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, GemfileExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.BundlerFilePath, GemfileExtractor)
}
