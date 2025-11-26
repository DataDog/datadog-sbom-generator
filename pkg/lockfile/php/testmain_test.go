package php_test

import (
	"os"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"

	"github.com/DataDog/datadog-sbom-generator/internal/testutility"
)

func TestMain(m *testing.M) {
	testutil.MockAllMatchers()
	code := m.Run()

	testutility.CleanSnapshots(m)
	os.Exit(code)
}
