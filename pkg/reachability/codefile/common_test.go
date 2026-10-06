package codefile

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_recordMatch_KeepsEarliestColumnOnTheSameLine checks that which match is kept doesn't
// depend on the order matches are recorded in.
func Test_recordMatch_KeepsEarliestColumnOnTheSameLine(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.19"
	const advisoryID = "CVE-2025-9012"

	atColumn := func(column int) models.PackageLocation {
		return models.PackageLocation{Filename: "app.js", LineStart: 3, LineEnd: 3, ColumnStart: column, ColumnEnd: column + 5}
	}

	orders := map[string][]int{
		"earliest recorded first":  {5, 20, 30},
		"earliest recorded middle": {20, 5, 30},
		"earliest recorded last":   {30, 20, 5},
	}

	for name, columns := range orders {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detectionResults := models.DetectionResults{}
			for _, column := range columns {
				recordMatch(detectionResults, purl, advisoryID, "match", atColumn(column))
			}

			locations := detectionResults[purl][advisoryID]
			require.Len(t, locations, 1)
			assert.Equal(t, 5, locations[0].ColumnStart)
		})
	}
}
