package models

import (
	"encoding/json"
	"testing"
)

func TestPackageLocation_Role_JSONMarshal_Manifest(t *testing.T) {
	t.Parallel()

	loc := PackageLocation{
		Filename:    "pom.xml",
		LineStart:   1,
		LineEnd:     5,
		ColumnStart: 1,
		ColumnEnd:   20,
		Role:        LocationRoleManifest,
	}

	data, err := json.Marshal(loc)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	role, ok := unmarshaled["role"]
	if !ok {
		t.Fatal("expected 'role' field in JSON output")
	}
	if role != "manifest" {
		t.Errorf("expected role 'manifest', got %q", role)
	}
}

func TestPackageLocation_Role_JSONMarshal_Lockfile(t *testing.T) {
	t.Parallel()

	loc := PackageLocation{
		Filename:    "Cargo.lock",
		LineStart:   10,
		LineEnd:     12,
		ColumnStart: 1,
		ColumnEnd:   30,
		Role:        LocationRoleLockfile,
	}

	data, err := json.Marshal(loc)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	role, ok := unmarshaled["role"]
	if !ok {
		t.Fatal("expected 'role' field in JSON output")
	}
	if role != "lockfile" {
		t.Errorf("expected role 'lockfile', got %q", role)
	}
}

func TestPackageLocation_Role_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := PackageLocation{
		Filename:    "go.sum",
		LineStart:   3,
		LineEnd:     3,
		ColumnStart: 1,
		ColumnEnd:   50,
		Role:        LocationRoleLockfile,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var restored PackageLocation
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if restored.Role != original.Role {
		t.Errorf("expected Role %q after round-trip, got %q", original.Role, restored.Role)
	}
}

func TestPackageLocation_Role_HashDifferentiation(t *testing.T) {
	t.Parallel()

	base := PackageLocation{
		Filename:    "pom.xml",
		LineStart:   1,
		LineEnd:     5,
		ColumnStart: 1,
		ColumnEnd:   20,
	}

	manifest := base
	manifest.Role = LocationRoleManifest

	lockfile := base
	lockfile.Role = LocationRoleLockfile

	if manifest.Hash() == lockfile.Hash() {
		t.Error("expected manifest and lockfile roles to produce different hashes")
	}

	if base.Hash() == manifest.Hash() {
		t.Error("expected empty role and manifest role to produce different hashes")
	}
}

func TestPackageLocation_Role_OmitEmpty(t *testing.T) {
	t.Parallel()

	loc := PackageLocation{
		Filename:    "pom.xml",
		LineStart:   1,
		LineEnd:     5,
		ColumnStart: 1,
		ColumnEnd:   20,
	}

	data, err := json.Marshal(loc)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var unmarshaled map[string]interface{}
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if _, ok := unmarshaled["role"]; ok {
		t.Error("expected 'role' field to be omitted when empty")
	}
}

func TestPackageLocation_Role_IsValid_BackwardCompat(t *testing.T) {
	t.Parallel()

	loc := PackageLocation{
		Filename:    "pom.xml",
		LineStart:   1,
		LineEnd:     5,
		ColumnStart: 1,
		ColumnEnd:   20,
	}

	if !loc.IsValid() {
		t.Error("expected IsValid()=true with empty Role (backward compatibility)")
	}
}
