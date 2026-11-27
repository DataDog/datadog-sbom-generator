package purl_test

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/purl"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestGitHubActionsPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pkgName string
		version string
		want    string
	}{
		{name: "tag", pkgName: "actions/checkout", version: "v4.1.1", want: "pkg:githubactions/actions/checkout@v4.1.1"},
		{name: "commit", pkgName: "actions/checkout", version: "b4ffde65f46336ab88eb53be808477a3936bae11", want: "pkg:githubactions/actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"},
		{name: "case is kept", pkgName: "Azure/Login", version: "v2", want: "pkg:githubactions/Azure/Login@v2"},
		{name: "branch with a slash", pkgName: "octo-org/shared", version: "release/v2", want: "pkg:githubactions/octo-org/shared@release%2Fv2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := purl.FromNameVersionEcosystem(tt.pkgName, tt.version, string(models.EcosystemGitHubActions))
			if err != nil {
				t.Fatalf("Got unexpected error: %v", err)
			}
			if got.ToString() != tt.want {
				t.Errorf("got %s; want %s", got.ToString(), tt.want)
			}
		})
	}
}

func TestGitHubActionsPURL_InvalidName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "checkout", "actions/", "a/b/c"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := purl.FromNameVersionEcosystem(name, "v4", string(models.EcosystemGitHubActions)); err == nil {
				t.Errorf("Expected an error for %q", name)
			}
		})
	}
}
