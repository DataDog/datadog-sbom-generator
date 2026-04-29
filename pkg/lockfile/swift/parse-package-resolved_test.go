package swift_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/swift"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestPackageResolvedExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty path",
			path: "",
			want: false,
		},
		{
			name: "Package.resolved",
			path: "Package.resolved",
			want: true,
		},
		{
			name: "nested Package.resolved",
			path: "path/to/my/Package.resolved",
			want: true,
		},
		{
			name: "Package.resolved as directory",
			path: "path/to/my/Package.resolved/file",
			want: false,
		},
		{
			name: "Package.resolved with extra extension",
			path: "path/to/my/Package.resolved.bak",
			want: false,
		},
		{
			name: "wrong filename",
			path: "path/to/my/package.resolved",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := swift.PackageResolvedExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParsePackageResolved_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageResolved_InvalidJSON(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageResolved_Empty(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageResolved_NoPins(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/no-pins-v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageResolved_OnePackageV1(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/one-package-v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.4.3",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}

func TestParsePackageResolved_OnePackageV2(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/one-package-v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.6.1",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}

func TestParsePackageResolved_OnePackageV3(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/one-package-v3.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.9.0",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}

func TestParsePackageResolved_TwoPackagesV2(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/two-packages-v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.6.1",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
		{
			Name:           "github.com/apple/swift-argument-parser",
			Version:        "1.2.0",
			Commit:         "fee6933f37fde9d3e241f557bcc65d8afee098e5",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}

func TestParsePackageResolved_MixedStatesV2(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/mixed-states-v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.6.1",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
		{
			Name:           "github.com/apple/swift-nio",
			Version:        "",
			Commit:         "a0e22235ec1e4e23c4a7a54e5ed2fba9e4e88a7b",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}

func TestParsePackageResolved_LocalPackageSkipped(t *testing.T) {
	t.Parallel()

	packages, err := swift.ParsePackageResolved("../fixtures/swift/with-local-package-v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// localSourceControl pins should be skipped
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "github.com/Alamofire/Alamofire",
			Version:        "5.6.1",
			Commit:         "f82c23a8a7ef8dc1a49a8bfc6a96883e79121864",
			PackageManager: models.SwiftPM,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		},
	})
}
