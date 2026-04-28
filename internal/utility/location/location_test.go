package location

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func validFilePosition() models.FilePosition {
	return models.FilePosition{
		Filename: "pom.xml",
		Line:     models.Position{Start: 1, End: 5},
		Column:   models.Position{Start: 1, End: 20},
	}
}

func TestNewPackageLocations_RolePropagatedToBlock(t *testing.T) {
	t.Parallel()

	block := validFilePosition()
	result := NewPackageLocations(block, nil, nil, models.LocationRoleManifest)

	if result.Block.Role != models.LocationRoleManifest {
		t.Errorf("expected Block.Role=%q, got %q", models.LocationRoleManifest, result.Block.Role)
	}
}

func TestNewPackageLocations_RolePropagatedToName(t *testing.T) {
	t.Parallel()

	block := validFilePosition()
	name := validFilePosition()
	result := NewPackageLocations(block, &name, nil, models.LocationRoleLockfile)

	if result.Name == nil {
		t.Fatal("expected Name to be non-nil")
	}
	if result.Name.Role != models.LocationRoleLockfile {
		t.Errorf("expected Name.Role=%q, got %q", models.LocationRoleLockfile, result.Name.Role)
	}
}

func TestNewPackageLocations_RolePropagatedToVersion(t *testing.T) {
	t.Parallel()

	block := validFilePosition()
	version := validFilePosition()
	result := NewPackageLocations(block, nil, &version, models.LocationRoleManifest)

	if result.Version == nil {
		t.Fatal("expected Version to be non-nil")
	}
	if result.Version.Role != models.LocationRoleManifest {
		t.Errorf("expected Version.Role=%q, got %q", models.LocationRoleManifest, result.Version.Role)
	}
}

func TestNewPackageLocations_NilNameAndVersionRemainNil(t *testing.T) {
	t.Parallel()

	block := validFilePosition()
	result := NewPackageLocations(block, nil, nil, models.LocationRoleManifest)

	if result.Name != nil {
		t.Error("expected Name to remain nil")
	}
	if result.Version != nil {
		t.Error("expected Version to remain nil")
	}
}
