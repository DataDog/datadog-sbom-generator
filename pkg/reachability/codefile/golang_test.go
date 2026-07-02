package codefile

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewGoReachableDetector(t *testing.T) {
	t.Parallel()
	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	assert.NotNil(t, detector)
}

func Test_Detect_Go_NoAdvisories(t *testing.T) {
	t.Parallel()
	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := make([]models.AdvisoryToCheck, 0)
	detectionResults := models.DetectionResults{}

	ctx := context.Background()

	err = detector.Detect(ctx, "", "testdata/vulnerable-function.go", detectionResults, advisoriesToCheck)

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}
