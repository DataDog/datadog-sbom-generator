package rust

import "github.com/DataDog/datadog-sbom-generator/pkg/models"

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	cargoPackageManager      = models.Crates
	cargoOfficiallySupported = true
)

// ============================================================================
// Cargo.lock Types
// ============================================================================

type CargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type CargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []CargoLockPackage `toml:"package"`
}

type CargoLockExtractor struct{}
