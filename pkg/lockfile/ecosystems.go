package lockfile

import "github.com/DataDog/datadog-sbom-generator/pkg/models"

// KnownEcosystems returns a list of ecosystems that `lockfile` supports
// automatically inferring an extractor for based on a file path.
func KnownEcosystems() []models.Ecosystem {
	return []models.Ecosystem{
		models.EcosystemNPM,
		models.EcosystemNuGet,
		models.EcosystemCratesIO,
		models.EcosystemRubyGems,
		models.EcosystemPackagist,
		models.EcosystemGo,
		models.EcosystemHex,
		models.EcosystemMaven,
		models.EcosystemPyPI,
		models.EcosystemPub,
		models.EcosystemConanCenter,
		models.EcosystemCRAN,
		// Disabled temporarily,
		// see https://github.com/google/osv-scanner/pull/128 discussion for additional context
		// models.EcosystemAlpine,
	}
}
