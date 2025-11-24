package semantic_test

import (
	"errors"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/semantic"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParse(t *testing.T) {
	t.Parallel()

	ecosystems := ecosystems()

	// todo: remove once CRAN is supported by lockfile
	ecosystems = append(ecosystems, "CRAN")

	for _, ecosystem := range ecosystems {
		_, err := semantic.Parse("", ecosystem)

		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			t.Errorf("'%s' is not a supported ecosystem", ecosystem)
		}
	}
}

func TestMustParse(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic - '%s'", r)
		}
	}()

	ecosystems := ecosystems()

	// todo: remove once CRAN is supported by lockfile
	ecosystems = append(ecosystems, "CRAN")

	for _, ecosystem := range ecosystems {
		semantic.MustParse("", ecosystem)
	}
}

func TestMustParse_Panic_UnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	defer func() { _ = recover() }()

	semantic.MustParse("", models.EcosystemOSSFuzz)

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an unsupported ecosystem")
}

func TestMustParse_Panic_UnknownEcosystem(t *testing.T) {
	t.Parallel()

	defer func() { _ = recover() }()

	semantic.MustParse("", "<unknown>")

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an unknown ecosystem")
}

// ecosystems returns a list of ecosystems that `lockfile` supports
// automatically inferring an extractor for based on a file path.
func ecosystems() []models.Ecosystem {
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
	}
}
