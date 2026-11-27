package githubactions

import (
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e ActionExtractor) ShouldExtract(path string) bool {
	base := filepath.Base(path)
	if base != "action.yml" && base != "action.yaml" {
		return false
	}

	// A file named action.yml in .github/workflows is a workflow
	return !WorkflowExtractor{}.ShouldExtract(path)
}

func (e ActionExtractor) IsOfficiallySupported() bool {
	return githubActionsOfficiallySupported
}

func (e ActionExtractor) PackageManager() models.PackageManager {
	return githubActionsPackageManager
}

// Extract reports the actions called by the steps of a composite action (runs.steps[*].uses).
// JavaScript and Docker actions have no steps, and files without a `runs` section are not actions.
func (e ActionExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	root, lines, err := parseYAMLDocument(f)
	if err != nil {
		return []extractor.PackageDetails{}, err
	}

	collector := newUsesCollector(f.Path(), lines, context)
	for _, step := range sequenceItems(mappingValue(mappingValue(root, "runs"), "steps")) {
		collector.collect(step)
	}

	return collector.packages, nil
}

var _ extractor.Extractor = ActionExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.GitHubActionsActionFilePath, ActionExtractor{})
}

func ParseAction(pathToAction string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToAction, ActionExtractor{})
}
