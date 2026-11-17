package sbomgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratedEvidencePreservesCodeownerStates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		enabled bool
		rules   *string
		want    *[]string
	}{
		{name: "disabled", rules: codeownerRule("* @org/team")},
		{name: "missing file", enabled: true, want: &[]string{}},
		{name: "no owning team", enabled: true, rules: codeownerRule("* @person"), want: &[]string{}},
		{name: "owning team", enabled: true, rules: codeownerRule("* @org/team"), want: &[]string{"org/team"}},
		{name: "team with long email domain", enabled: true, rules: codeownerRule("* @org/team person@example.engineering"), want: &[]string{"org/team"}},
		{name: "long email domain without team", enabled: true, rules: codeownerRule("* person@example.engineering"), want: &[]string{}},
		{name: "unrelated unicode path preserves team", enabled: true, rules: codeownerRule("* @org/team\n/données/ @org/data"), want: &[]string{"org/team"}},
		{name: "unrelated dollar path preserves team", enabled: true, rules: codeownerRule("* @org/team\n/$generated/ @org/generated"), want: &[]string{"org/team"}},
		{name: "invalid file", enabled: true, rules: codeownerRule("* !invalid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			lockfile, err := os.ReadFile("testdata/Cargo.lock")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.lock"), lockfile, 0600))
			if tc.rules != nil {
				require.NoError(t, os.WriteFile(filepath.Join(root, "CODEOWNERS"), []byte(*tc.rules), 0600))
			}
			options := DefaultOptions()
			options.ResolveCodeowners = tc.enabled
			encoded, err := GenerateSBOM([]string{root}, options)
			require.NoError(t, err)
			var bom cyclonedx.BOM
			require.NoError(t, json.Unmarshal(encoded, &bom))
			require.NotNil(t, bom.Components)
			var locations []models.PackageLocations
			for _, component := range *bom.Components {
				if component.Evidence == nil || component.Evidence.Occurrences == nil {
					continue
				}
				for _, occurrence := range *component.Evidence.Occurrences {
					var location models.PackageLocations
					require.NoError(t, json.Unmarshal([]byte(occurrence.Location), &location))
					locations = append(locations, location)
				}
			}
			require.NotEmpty(t, locations)
			for _, location := range locations {
				assert.Equal(t, tc.want, location.Codeowners, location.Block.Filename)
			}
		})
	}
}

func codeownerRule(value string) *string {
	return &value
}
