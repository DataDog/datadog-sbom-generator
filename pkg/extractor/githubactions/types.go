package githubactions

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	githubActionsPackageManager      = models.GitHubActions
	githubActionsOfficiallySupported = true
)

// ============================================================================
// Extractors
// ============================================================================

// WorkflowExtractor extracts the actions and reusable workflows referenced by the `uses:` keys of
// workflow files (.github/workflows/*.yml) and workflow templates (.github/workflow-templates/*.yml).
type WorkflowExtractor struct{}

// ActionExtractor extracts the actions referenced by the steps of composite actions (action.yml).
type ActionExtractor struct{}
