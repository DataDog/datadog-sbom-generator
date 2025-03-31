package codefile

import (
	"testing"

	"github.com/datadog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func Test_NewJavaReachableDetector(t *testing.T) {
	detector, err := NewJavaReachableDetector()
	assert.NoError(t, err)
	assert.NotNil(t, detector)
}

func Test_Detect_NoAdvisories(t *testing.T) {
	detector, err := NewJavaReachableDetector()
	assert.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := make([]models.AdvisoryToCheck, 0)
	detectionResults := models.DetectionResults{}

	detector.Detect("", "testdata/vulnerable-class.java", detectionResults, advisoriesToCheck)

	assert.Equal(t, 0, len(detectionResults))
}

func Test_Detect_ClassSymbolsFound(t *testing.T) {
	detector, err := NewJavaReachableDetector()
	assert.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:maven/org.example/Greeter@1.2.3",
			AdvisoryId: "CVE-2025-1234",
			Symbols: []models.Symbols{
				{
					Type:  "class",
					Name:  "Greeter",
					Value: "org.example",
				},
			},
		},
	}

	detectionResults := models.DetectionResults{}
	detector.Detect(".", "testdata/CVE-2025-1234/explicit-import/class.java", detectionResults, advisoriesToCheck)
	assert.Equal(t, 1, len(detectionResults))
	advisories, ok := detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(advisories))
	reachableSymbols, ok := advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(reachableSymbols))
	assert.Equal(t, "Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/explicit-import/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 8, reachableSymbols[0].LineStart)
	assert.Equal(t, 8, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 36, reachableSymbols[0].ColumnEnd)

	detectionResults = models.DetectionResults{}
	detector.Detect(".", "testdata/CVE-2025-1234/wildcard-import/class.java", detectionResults, advisoriesToCheck)
	assert.Equal(t, 1, len(detectionResults))
	advisories, ok = detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(advisories))
	reachableSymbols, ok = advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(reachableSymbols))
	assert.Equal(t, "Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/wildcard-import/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 8, reachableSymbols[0].LineStart)
	assert.Equal(t, 8, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 36, reachableSymbols[0].ColumnEnd)

	detectionResults = models.DetectionResults{}
	detector.Detect(".", "testdata/CVE-2025-1234/fully-qualified-name/class.java", detectionResults, advisoriesToCheck)
	assert.Equal(t, 1, len(detectionResults))
	advisories, ok = detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(advisories))
	reachableSymbols, ok = advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(reachableSymbols))
	assert.Equal(t, "org.example.Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/fully-qualified-name/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 6, reachableSymbols[0].LineStart)
	assert.Equal(t, 6, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 48, reachableSymbols[0].ColumnEnd)
}
