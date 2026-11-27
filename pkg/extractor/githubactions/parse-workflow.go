package githubactions

import (
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const githubDirectory = ".github"

// workflowDirectories are the directories of .github holding workflow files: workflows run by GitHub,
// and the workflow templates an organization offers in its .github repository.
var workflowDirectories = map[string]struct{}{
	"workflows":          {},
	"workflow-templates": {},
}

func (e WorkflowExtractor) ShouldExtract(path string) bool {
	extension := filepath.Ext(path)
	if extension != ".yml" && extension != ".yaml" {
		return false
	}

	directory := filepath.Dir(path)
	if _, ok := workflowDirectories[filepath.Base(directory)]; !ok {
		return false
	}

	return filepath.Base(filepath.Dir(directory)) == githubDirectory
}

func (e WorkflowExtractor) IsOfficiallySupported() bool {
	return githubActionsOfficiallySupported
}

func (e WorkflowExtractor) PackageManager() models.PackageManager {
	return githubActionsPackageManager
}

// Extract reports the reusable workflows called by jobs (jobs.<id>.uses) and the actions called by
// steps (jobs.<id>.steps[*].uses).
func (e WorkflowExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	root, lines, err := parseYAMLDocument(f)
	if err != nil {
		return []extractor.PackageDetails{}, err
	}

	collector := newUsesCollector(f.Path(), lines, context)
	for _, job := range mappingValues(mappingValue(root, "jobs")) {
		collector.collect(job)

		for _, step := range sequenceItems(mappingValue(job, "steps")) {
			collector.collect(step)
		}
	}

	return collector.packages, nil
}

var _ extractor.Extractor = WorkflowExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.GitHubActionsWorkflowFilePath, WorkflowExtractor{})
}

func ParseWorkflow(pathToWorkflow string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToWorkflow, WorkflowExtractor{})
}
