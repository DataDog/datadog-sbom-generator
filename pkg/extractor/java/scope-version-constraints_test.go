package java_test

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-sbom-generator/internal/testutility"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func TestScopeVersionConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture string
		want    map[string][]string
	}{
		{
			name:    "parent in a sibling folder is also keyed under the top-most child",
			fixture: "sibling-parent",
			want: map[string][]string{
				"org.yaml:snakeyaml@2.4": {"c6-child/pom.xml:3", "c6-parent/pom.xml:9"},
			},
		},
		{
			name:    "child re-pinning an inherited package keeps only its own version",
			fixture: "child-repin",
			want: map[string][]string{
				"com.fasterxml.jackson.core:jackson-databind@2.18.0": {"child/pom.xml:3", "parent/pom.xml:14"},
				"org.yaml:snakeyaml@2.3": {"parent/pom.xml:9"},
				"org.yaml:snakeyaml@2.4": {"child/pom.xml:12"},
			},
		},
		{
			name:    "root to sibling parent to child only adds the sibling parent's pins",
			fixture: "two-level",
			want: map[string][]string{
				"junit:junit@4.13.2":     {"pom.xml:9"},
				"org.yaml:snakeyaml@2.4": {"child/pom.xml:3", "parent/pom.xml:12"},
			},
		},
		{
			name:    "aggregator without inheritors nor dependencies drops its pins",
			fixture: "aggregator-unused",
			want: map[string][]string{
				"com.fasterxml.jackson.core:jackson-databind@2.18.0": {"pom.xml:9"},
			},
		},
		{
			// The root is an aggregator too: agg/inheritor sits in its folder without inheriting it.
			name:    "aggregator pins move to their inheriting members only",
			fixture: "aggregator-mixed",
			want: map[string][]string{
				"com.fasterxml.jackson.core:jackson-databind@2.18.0": {"agg/member/pom.xml:3"},
				"org.yaml:snakeyaml@2.4": {"agg/inheritor/pom.xml:3"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root, pkgs := extractFixture(t, tt.fixture)
			scoped := java.ScopeVersionConstraints(&reporter.VoidReporter{}, pkgs)

			require.Equal(t, tt.want, keyedPins(t, root, scoped))
		})
	}
}

func TestScopeVersionConstraints_NormalLayoutUnchanged(t *testing.T) {
	t.Parallel()

	root, pkgs := extractFixture(t, "normal")
	scoped := java.ScopeVersionConstraints(&reporter.VoidReporter{}, slices.Clone(pkgs))

	require.Equal(t, pkgs, scoped)
	testutility.NewSnapshot().MatchJSON(t, keyedPins(t, root, scoped))
}

// extractFixture extracts every pom.xml of a scope fixture with absolute paths, as the scanner does.
func extractFixture(t *testing.T, fixture string) (string, []extractor.PackageDetails) {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", "fixtures", "maven", "scope", fixture))
	require.NoError(t, err)

	var pkgs []extractor.PackageDetails
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Name() != models.MavenFilePath.String() {
			return err
		}
		extracted, err := java.ParseMavenLock(path)
		if err != nil {
			return err
		}
		for i := range extracted {
			extracted[i].Source = models.SourceInfo{Path: path}
		}
		pkgs = append(pkgs, extracted...)

		return nil
	})
	require.NoError(t, err)

	return root, pkgs
}

// keyedPins maps each pin to the sorted "file:line" blocks it is keyed under, relative to root.
func keyedPins(t *testing.T, root string, pkgs []extractor.PackageDetails) map[string][]string {
	t.Helper()

	pins := map[string][]string{}
	for _, pkg := range pkgs {
		if !pkg.IsVersionConstraint {
			continue
		}
		file, err := filepath.Rel(root, pkg.BlockLocation.Filename)
		require.NoError(t, err)

		pin := pkg.Name + "@" + pkg.Version
		block := fmt.Sprintf("%s:%d", filepath.ToSlash(file), pkg.BlockLocation.Line.Start)
		if !slices.Contains(pins[pin], block) {
			pins[pin] = append(pins[pin], block)
		}
	}
	for _, blocks := range pins {
		slices.Sort(blocks)
	}

	return pins
}
