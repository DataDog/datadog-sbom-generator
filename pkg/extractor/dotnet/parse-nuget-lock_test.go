package dotnet_test

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/dotnet"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
)

func TestNuGetLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "packages.lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.packages.lock.json",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := dotnet.NuGetLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNuGetLock_InvalidVersion(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/empty.v0.json")

	testutil.ExpectErrContaining(t, err, "unsupported lock file version 0")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}
