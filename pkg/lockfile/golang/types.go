package golang

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	goPackageManager      = models.Golang
	goFilePath            = models.GolangFilePath
	goOfficiallySupported = true
)

// ============================================================================
// Version Constants
// ============================================================================

const unknownVersion = "v0.0.0-unresolved-version"

// ============================================================================
// Extractor Type
// ============================================================================

type GoLockExtractor struct{}
