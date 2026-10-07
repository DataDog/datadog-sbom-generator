package reachability

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_getAdvisoriesToCheckPerLanguage_NoAdvisoriesToCheck(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID:      "testing-123",
		Results: []http.SymbolsForPurl{},
	}

	expected := models.AdvisoriesToCheckPerLanguage{}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resolveVulnerableSymbolsResponse)

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

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resolveVulnerableSymbolsResponse)

	assert.Equal(t, expected, advisoriesToCheckPerLanguage)
}

func Test_getAdvisoriesToCheckPerLanguage_GoPurlRoutesToGoLanguage(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{
			{
				Purl: "pkg:golang/github.com/foo/bar@1.2.3",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-5678",
						Symbols: []http.Symbol{
							{
								Type:  "function",
								Value: "github.com/foo/bar",
								Name:  "Parse",
							},
						},
					},
				},
			},
		},
	}

	expected := models.AdvisoriesToCheckPerLanguage{
		"go": {
			{
				Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
				AdvisoryID: "CVE-2025-5678",
				Symbols: []models.Symbols{
					{
						Type:  "function",
						Value: "github.com/foo/bar",
						Name:  "Parse",
					},
				},
			},
		},
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resolveVulnerableSymbolsResponse)

	assert.Equal(t, expected, advisoriesToCheckPerLanguage)
}

func Test_getAdvisoriesToCheckPerLanguage_UnsupportedOrMalformedPurlsAreSkipped(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{
			{
				// pypi has no reachability detector registered, so it should be skipped like any
				// other unsupported PURL type.
				Purl: "pkg:pypi/lodash@4.17.21",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-1111",
						Symbols: []http.Symbol{
							{Type: "function", Value: "lodash", Name: "merge"},
						},
					},
				},
			},
			{
				Purl: "not-a-purl",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-2222",
						Symbols:    []http.Symbol{{Type: "function", Value: "x", Name: "y"}},
					},
				},
			},
		},
	}

	expected := models.AdvisoriesToCheckPerLanguage{}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resolveVulnerableSymbolsResponse)

	assert.Equal(t, expected, advisoriesToCheckPerLanguage)
}

func Test_getAdvisoriesToCheckPerLanguage_NpmPurlRoutesToJavaScriptLanguage(t *testing.T) {
	t.Parallel()

	resolveVulnerableSymbolsResponse := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{
			{
				Purl: "pkg:npm/lodash@4.17.21",
				VulnerableSymbols: []http.SymbolDetails{
					{
						AdvisoryID: "CVE-2025-1111",
						Symbols: []http.Symbol{
							{
								Type:  "function",
								Value: "lodash",
								Name:  "merge",
							},
						},
					},
				},
			},
		},
	}

	expected := models.AdvisoriesToCheckPerLanguage{
		"javascript": {
			{
				Purl:       "pkg:npm/lodash@4.17.21",
				AdvisoryID: "CVE-2025-1111",
				Symbols: []models.Symbols{
					{
						Type:  "function",
						Value: "lodash",
						Name:  "merge",
					},
				},
			},
		},
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resolveVulnerableSymbolsResponse)

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

// A reporter with no expectations fails the test on any call: filtering must be silent.
func Test_getAdvisoriesToCheckPerLanguage_UnsupportedSymbolTypesAreFiltered(t *testing.T) {
	t.Parallel()

	strictReporter := reporter.NewMockReporter(gomock.NewController(t))

	resp := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{
			{
				Purl: "pkg:golang/github.com/foo/bar@1.2.3",
				VulnerableSymbols: []http.SymbolDetails{
					{AdvisoryID: "GO-MIXED", Symbols: []http.Symbol{
						{Type: "function", Value: "github.com/foo/bar", Name: "Parse"},
						{Type: "class", Value: "github.com/foo/bar", Name: "Parser"},
					}},
					{AdvisoryID: "GO-UNSUPPORTED", Symbols: []http.Symbol{
						{Type: "class", Value: "github.com/foo/bar", Name: "Parser"},
					}},
				},
			},
			{
				Purl: "pkg:maven/org.example/foo@1.2.3",
				VulnerableSymbols: []http.SymbolDetails{
					{AdvisoryID: "JAVA-MIXED", Symbols: []http.Symbol{
						{Type: "class", Value: "org.example", Name: "Foo"},
						{Type: "function", Value: "org.example", Name: "foo"},
					}},
					{AdvisoryID: "JAVA-UNSUPPORTED", Symbols: []http.Symbol{
						{Type: "function", Value: "org.example", Name: "foo"},
					}},
				},
			},
			{
				Purl: "pkg:npm/lodash@4.17.19",
				VulnerableSymbols: []http.SymbolDetails{
					{AdvisoryID: "NPM-MIXED", Symbols: []http.Symbol{
						{Type: "function", Value: "lodash", Name: "merge"},
						{Type: "class", Value: "lodash", Name: "Merger"},
						{Type: "method", Value: "lodash", Name: "chain"},
					}},
					{AdvisoryID: "NPM-UNSUPPORTED", Symbols: []http.Symbol{
						{Type: "method", Value: "lodash", Name: "chain"},
					}},
				},
			},
		},
	}

	expected := models.AdvisoriesToCheckPerLanguage{
		"go": {{
			Purl: "pkg:golang/github.com/foo/bar@1.2.3", AdvisoryID: "GO-MIXED",
			Symbols: []models.Symbols{{Type: "function", Value: "github.com/foo/bar", Name: "Parse"}},
		}},
		"java": {{
			Purl: "pkg:maven/org.example/foo@1.2.3", AdvisoryID: "JAVA-MIXED",
			Symbols: []models.Symbols{{Type: "class", Value: "org.example", Name: "Foo"}},
		}},
		"javascript": {{
			Purl: "pkg:npm/lodash@4.17.19", AdvisoryID: "NPM-MIXED",
			Symbols: []models.Symbols{
				{Type: "function", Value: "lodash", Name: "merge"},
				{Type: "class", Value: "lodash", Name: "Merger"},
			},
		}},
	}

	assert.Equal(t, expected, getAdvisoriesToCheckPerLanguage(strictReporter, resp))
}

func Test_getAdvisoriesToCheckPerLanguage_LanguageWithOnlyUnsupportedSymbolsIsOmitted(t *testing.T) {
	t.Parallel()

	resp := http.ResolveVulnerableSymbolsResponse{
		ID: "testing-123",
		Results: []http.SymbolsForPurl{{
			Purl: "pkg:golang/github.com/foo/bar@1.2.3",
			VulnerableSymbols: []http.SymbolDetails{{
				AdvisoryID: "GO-UNSUPPORTED",
				Symbols:    []http.Symbol{{Type: "class", Value: "github.com/foo/bar", Name: "Parser"}},
			}},
		}},
	}

	assert.Equal(t, models.AdvisoriesToCheckPerLanguage{}, getAdvisoriesToCheckPerLanguage(&reporter.VoidReporter{}, resp))
}
