package reachability

import (
	"testing"

	"github.com/datadog/datadog-sbom-generator/internal/http"
	"github.com/datadog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func Test_getAdvisoriesToCheckPerLanguage_NoAdvisoriesToCheck(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID:      "testing-123",
		Results: []http.SymbolsForPurl{},
	}

	expected := models.AdvisoriesToCheckPerLanguage{}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(resolveVulnerableSymbolsResponse)

	assert.Equal(t, expected, advisoriesToCheckPerLanguage)
}

func Test_getAdvisoriesToCheckPerLanguage_HasAdvisoriesToCheck(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{
			{
				Purl: "pkg:maven/org.example/foo@1.2.3",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-1234",
						Symbols: []http.Symbol{
							{
								Type:  "class",
								Value: "Foo",
								Name:  "org.example",
							},
							{
								Type:  "class",
								Value: "foo",
								Name:  "org.example",
							},
						},
					},
				},
			},
			{
				Purl: "pkg:maven/org.example/bar@9.8.7",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-9876",
						Symbols: []http.Symbol{
							{
								Type:  "class",
								Value: "Bar",
								Name:  "org.example",
							},
						},
					},
					{
						AdvisoryID: "CVE-2025-0000",
						Symbols: []http.Symbol{
							{
								Type:  "class",
								Value: "Bar",
								Name:  "org.example",
							},
						},
					},
				},
			},
		},
	}

	expected := models.AdvisoriesToCheckPerLanguage{
		"java": {
			{
				Purl:       "pkg:maven/org.example/foo@1.2.3",
				AdvisoryID: "CVE-2025-1234",
				Symbols: []models.Symbols{
					{
						Type:  "class",
						Value: "Foo",
						Name:  "org.example",
					},
					{
						Type:  "class",
						Value: "foo",
						Name:  "org.example",
					},
				},
			},
			{
				Purl:       "pkg:maven/org.example/bar@9.8.7",
				AdvisoryID: "CVE-2025-9876",
				Symbols: []models.Symbols{
					{
						Type:  "class",
						Value: "Bar",
						Name:  "org.example",
					},
				},
			},
			{
				Purl:       "pkg:maven/org.example/bar@9.8.7",
				AdvisoryID: "CVE-2025-0000",
				Symbols: []models.Symbols{
					{
						Type:  "class",
						Value: "Bar",
						Name:  "org.example",
					},
				},
			},
		},
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(resolveVulnerableSymbolsResponse)

	assert.Equal(t, expected, advisoriesToCheckPerLanguage)
}

func Test_getPurlsToReachabilityAnalysisResults_Empty(t *testing.T) {
	t.Parallel()

	advisories := models.AdvisoriesToCheckPerLanguage{}
	detections := models.DetectionResults{}

	expected := models.PurlToReachabilityAnalysisResults{}
	result := getPurlsToReachabilityAnalysisResults(advisories, detections)
	assert.Equal(t, expected, result)
}

func Test_getPurlsToReachabilityAnalysisResults_MultipleAdvisoriesAndNoDetections(t *testing.T) {
	t.Parallel()

	advisories := models.AdvisoriesToCheckPerLanguage{
		"java": {
			{
				Purl:       "pkg:maven/org.example/foo@1.2.3",
				AdvisoryID: "CVE-2025-1234",
				Symbols:    []models.Symbols{{}},
			},
			{
				Purl:       "pkg:maven/org.example/foo@1.2.3",
				AdvisoryID: "CVE-2025-9876",
				Symbols:    []models.Symbols{{}},
			},
		},
	}

	detections := models.DetectionResults{}

	expected := models.PurlToReachabilityAnalysisResults{
		"pkg:maven/org.example/foo@1.2.3": &models.ReachabilityAnalysisResults{
			AdvisoryIdsChecked: []string{
				"CVE-2025-1234",
				"CVE-2025-9876",
			},
			ReachableVulnerabilities: []models.ReachableVulnerability{},
		},
	}

	result := getPurlsToReachabilityAnalysisResults(advisories, detections)
	assert.Equal(t, expected, result)
}

func Test_getPurlsToReachabilityAnalysisResults_MultipleAdvisoriesWithDetections(t *testing.T) {
	t.Parallel()

	advisories := models.AdvisoriesToCheckPerLanguage{
		"java": {
			{
				Purl:       "pkg:maven/org.example/foo@1.2.3",
				AdvisoryID: "CVE-2025-1234",
				Symbols:    []models.Symbols{{}},
			},
			{
				Purl:       "pkg:maven/org.example/bar@9.8.7",
				AdvisoryID: "CVE-2025-1234",
				Symbols:    []models.Symbols{{}},
			},
			{
				Purl:       "pkg:maven/org.example/bar@9.8.7",
				AdvisoryID: "CVE-2025-9876",
				Symbols:    []models.Symbols{{}},
			},
		},
	}

	detections := models.DetectionResults{
		"pkg:maven/org.example/foo@1.2.3": {
			"CVE-2025-1234": {
				{
					Symbol: "Foo",
					PackageLocation: models.PackageLocation{
						Filename:    "plip/Main.java",
						LineStart:   5,
						LineEnd:     5,
						ColumnStart: 10,
						ColumnEnd:   13,
					},
				},
			},
		},
		"pkg:maven/org.example/bar@9.8.7": {
			"CVE-2025-9876": {
				{
					Symbol: "Bar",
					PackageLocation: models.PackageLocation{
						Filename:    "plop/Main.java",
						LineStart:   5,
						LineEnd:     5,
						ColumnStart: 10,
						ColumnEnd:   13,
					},
				},
			},
		},
	}

	expected := models.PurlToReachabilityAnalysisResults{
		"pkg:maven/org.example/foo@1.2.3": &models.ReachabilityAnalysisResults{
			AdvisoryIdsChecked: []string{
				"CVE-2025-1234",
			},
			ReachableVulnerabilities: []models.ReachableVulnerability{
				{
					AdvisoryID: "CVE-2025-1234",
					ReachableSymbolLocations: []models.ReachableSymbolLocation{
						{
							Symbol: "Foo",
							PackageLocation: models.PackageLocation{
								Filename:    "plip/Main.java",
								LineStart:   5,
								LineEnd:     5,
								ColumnStart: 10,
								ColumnEnd:   13,
							},
						},
					},
				},
			},
		},
		"pkg:maven/org.example/bar@9.8.7": &models.ReachabilityAnalysisResults{
			AdvisoryIdsChecked: []string{
				"CVE-2025-1234",
				"CVE-2025-9876",
			},
			ReachableVulnerabilities: []models.ReachableVulnerability{
				{
					AdvisoryID: "CVE-2025-9876",
					ReachableSymbolLocations: []models.ReachableSymbolLocation{
						{
							Symbol: "Bar",
							PackageLocation: models.PackageLocation{
								Filename:    "plop/Main.java",
								LineStart:   5,
								LineEnd:     5,
								ColumnStart: 10,
								ColumnEnd:   13,
							},
						},
					},
				},
			},
		},
	}

	result := getPurlsToReachabilityAnalysisResults(advisories, detections)
	assert.Equal(t, expected, result)
}
