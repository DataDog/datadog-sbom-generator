package codefile

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewJavaReachableDetector(t *testing.T) {
	t.Parallel()
	detector, err := NewJavaReachableDetector()
	require.NoError(t, err)
	defer detector.Close()

	assert.NotNil(t, detector)
}

func Test_Detect_NoAdvisories(t *testing.T) {
	t.Parallel()
	detector, err := NewJavaReachableDetector()
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := make([]models.AdvisoryToCheck, 0)
	detectionResults := models.DetectionResults{}

	detector.Detect("", "testdata/vulnerable-class.java", detectionResults, advisoriesToCheck)

	assert.Empty(t, detectionResults)
}

func Test_Detect_ClassSymbolsFound(t *testing.T) {
	t.Parallel()
	detector, err := NewJavaReachableDetector()
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:maven/org.example/Greeter@1.2.3",
			AdvisoryID: "CVE-2025-1234",
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
	assert.Len(t, detectionResults, 1)
	advisories, ok := detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Len(t, advisories, 1)
	reachableSymbols, ok := advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Len(t, reachableSymbols, 1)
	assert.Equal(t, "Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/explicit-import/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 8, reachableSymbols[0].LineStart)
	assert.Equal(t, 8, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 36, reachableSymbols[0].ColumnEnd)

	detectionResults = models.DetectionResults{}
	detector.Detect(".", "testdata/CVE-2025-1234/wildcard-import/class.java", detectionResults, advisoriesToCheck)
	assert.Len(t, detectionResults, 1)
	advisories, ok = detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Len(t, advisories, 1)
	reachableSymbols, ok = advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Len(t, reachableSymbols, 1)
	assert.Equal(t, "Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/wildcard-import/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 8, reachableSymbols[0].LineStart)
	assert.Equal(t, 8, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 36, reachableSymbols[0].ColumnEnd)

	detectionResults = models.DetectionResults{}
	detector.Detect(".", "testdata/CVE-2025-1234/fully-qualified-name/class.java", detectionResults, advisoriesToCheck)
	assert.Len(t, detectionResults, 1)
	advisories, ok = detectionResults["pkg:maven/org.example/Greeter@1.2.3"]
	assert.True(t, ok)
	assert.Len(t, advisories, 1)
	reachableSymbols, ok = advisories["CVE-2025-1234"]
	assert.True(t, ok)
	assert.Len(t, reachableSymbols, 1)
	assert.Equal(t, "org.example.Greeter", reachableSymbols[0].Symbol)
	assert.Equal(t, "testdata/CVE-2025-1234/fully-qualified-name/class.java", reachableSymbols[0].Filename)
	assert.Equal(t, 6, reachableSymbols[0].LineStart)
	assert.Equal(t, 6, reachableSymbols[0].LineEnd)
	assert.Equal(t, 29, reachableSymbols[0].ColumnStart)
	assert.Equal(t, 48, reachableSymbols[0].ColumnEnd)
}
