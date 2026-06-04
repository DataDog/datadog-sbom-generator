package sbomgen

import (
	"encoding/json"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// mavenFileComponent creates a file-type CycloneDX component representing a
// pom.xml, as produced by ExtractMavenPomArtifactIds. If parentPath is
// non-empty it sets the datadog:maven-parent-pom property, encoding the <parent>
// relationship unambiguously.
func mavenFileComponent(pomPath, parentPath string) cyclonedx.Component {
	props := []cyclonedx.Property{
		{Name: mavenPackageProperty, Value: "pkg:maven/com.example/" + pomPath + "@1.0"},
	}
	if parentPath != "" {
		props = append(props, cyclonedx.Property{
			Name:  mavenParentPomProperty,
			Value: parentPath,
		})
	}

	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeFile,
		BOMRef:     pomPath,
		Name:       pomPath,
		Properties: &props,
	}
}

// mavenComponent builds a CycloneDX component with a manifest occurrence for
// the given pom.xml path, as the SBOM generator would emit it.
func mavenComponent(name, pomPath string) cyclonedx.Component {
	return componentWithOccurrences(name, "1.0.0", makeLocation(pomPath, "manifest"))
}

// mavenDep builds a CycloneDX Dependency entry for a POM pointing to one or
// more direct dependencies (parent and/or local module POMs).
func mavenDep(ref string, dependsOn ...string) cyclonedx.Dependency {
	return cyclonedx.Dependency{Ref: ref, Dependencies: &dependsOn}
}

// makeSBOMWithDeps builds CycloneDX JSON bytes from components and explicit
// dependency entries. Use instead of makeSBOM when bom.Dependencies must be
// populated so that ProcessorContext.FileDependencies is non-empty.
func makeSBOMWithDeps(components []cyclonedx.Component, deps []cyclonedx.Dependency) []byte {
	bom := cyclonedx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cyclonedx.SpecVersion1_5,
		Components:   &components,
		Dependencies: &deps,
	}
	b, err := json.Marshal(bom)
	if err != nil {
		panic(err)
	}

	return b
}

// pomFile is a shorthand for a pom.xml BuildFile with no RepoPath.
func pomFile(path string) BuildFile {
	return BuildFile{FileType: FileTypePomXML, FilePath: path}
}

// --- Tests ---

// TestMavenProcessor_SingleRootPom verifies that a standalone pom.xml
// (no parent, no modules) gets empty dependencies and an ID from the purl.
func TestMavenProcessor_SingleRootPom(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		mavenFileComponent("pom.xml", ""),
		mavenComponent("com.example:app", "pom.xml"),
	})

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}
	rel := result[pomFile("pom.xml")]
	if rel.ID != "com.example:pom.xml" {
		t.Errorf("expected ID=com.example:pom.xml, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}

// TestMavenProcessor_ParentChild verifies a simple two-level hierarchy:
//
//	pom.xml
//	└── child/pom.xml
//
// child depends on pom.xml (its parent). root has no dependencies.
func TestMavenProcessor_ParentChild(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", ""),
			mavenFileComponent("child/pom.xml", "pom.xml"),
			mavenComponent("com.example:parent", "pom.xml"),
			mavenComponent("com.example:child", "child/pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("child/pom.xml", "pom.xml"),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(result), result)
	}

	root := result[pomFile("pom.xml")]
	if root.ID != "com.example:pom.xml" {
		t.Errorf("root: expected ID=com.example:pom.xml, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	child := result[pomFile("child/pom.xml")]
	if child.ID != "com.example:child/pom.xml" {
		t.Errorf("child: expected ID=com.example:child/pom.xml, got %q", child.ID)
	}
	if len(child.Dependencies) != 1 || child.Dependencies[0] != pomFile("pom.xml") {
		t.Errorf("child: expected Dependencies=[pom.xml], got %v", child.Dependencies)
	}
}

// TestMavenProcessor_MultiModule verifies a flat multi-module layout:
//
//	pom.xml (aggregator)
//	├── core/pom.xml
//	├── web/pom.xml
//	└── integration-tests/pom.xml
//
// Each child depends on pom.xml (its parent). Root has no dependencies.
func TestMavenProcessor_MultiModule(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", ""),
			mavenFileComponent("core/pom.xml", "pom.xml"),
			mavenFileComponent("web/pom.xml", "pom.xml"),
			mavenFileComponent("integration-tests/pom.xml", "pom.xml"),
			mavenComponent("com.example:parent", "pom.xml"),
			mavenComponent("com.example:core", "core/pom.xml"),
			mavenComponent("com.example:web", "web/pom.xml"),
			mavenComponent("com.example:integration-tests", "integration-tests/pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("core/pom.xml", "pom.xml"),
			mavenDep("web/pom.xml", "pom.xml"),
			mavenDep("integration-tests/pom.xml", "pom.xml"),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 4 {
		t.Fatalf("expected 4 entries, got %d: %v", len(result), result)
	}

	root := result[pomFile("pom.xml")]
	if root.ID != "com.example:pom.xml" {
		t.Errorf("root: expected ID=com.example:pom.xml, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	for _, childPath := range []string{"core/pom.xml", "integration-tests/pom.xml", "web/pom.xml"} {
		rel := result[pomFile(childPath)]
		expectedID := "com.example:" + childPath
		if rel.ID != expectedID {
			t.Errorf("%s: expected ID=%s, got %q", childPath, expectedID, rel.ID)
		}
		if len(rel.Dependencies) != 1 || rel.Dependencies[0] != pomFile("pom.xml") {
			t.Errorf("%s: expected Dependencies=[pom.xml], got %v", childPath, rel.Dependencies)
		}
	}
}

// TestMavenProcessor_DeepHierarchy verifies a three-level chain:
//
//	pom.xml
//	└── module/pom.xml
//	    └── module/sub/pom.xml
//
// Transitive closure: root.Dependencies=[], mid.Dependencies=[pom.xml],
// leaf.Dependencies=[module/pom.xml, pom.xml] (sorted by FilePath).
func TestMavenProcessor_DeepHierarchy(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", ""),
			mavenFileComponent("module/pom.xml", "pom.xml"),
			mavenFileComponent("module/sub/pom.xml", "module/pom.xml"),
			mavenComponent("com.example:root", "pom.xml"),
			mavenComponent("com.example:module", "module/pom.xml"),
			mavenComponent("com.example:sub", "module/sub/pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("module/pom.xml", "pom.xml"),
			mavenDep("module/sub/pom.xml", "module/pom.xml"),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	root := result[pomFile("pom.xml")]
	if root.ID != "com.example:pom.xml" {
		t.Errorf("root: expected ID=com.example:pom.xml, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	mid := result[pomFile("module/pom.xml")]
	if mid.ID != "com.example:module/pom.xml" {
		t.Errorf("module: expected ID=com.example:module/pom.xml, got %q", mid.ID)
	}
	if len(mid.Dependencies) != 1 || mid.Dependencies[0] != pomFile("pom.xml") {
		t.Errorf("module: expected Dependencies=[pom.xml], got %v", mid.Dependencies)
	}

	leaf := result[pomFile("module/sub/pom.xml")]
	if leaf.ID != "com.example:module/sub/pom.xml" {
		t.Errorf("sub: expected ID=com.example:module/sub/pom.xml, got %q", leaf.ID)
	}
	// Transitive: leaf depends on module/pom.xml AND pom.xml, sorted by FilePath.
	if len(leaf.Dependencies) != 2 {
		t.Fatalf("sub: expected 2 Dependencies, got %v", leaf.Dependencies)
	}
	if leaf.Dependencies[0] != pomFile("module/pom.xml") {
		t.Errorf("sub: expected Dependencies[0]=module/pom.xml, got %v", leaf.Dependencies[0])
	}
	if leaf.Dependencies[1] != pomFile("pom.xml") {
		t.Errorf("sub: expected Dependencies[1]=pom.xml, got %v", leaf.Dependencies[1])
	}
}

// TestMavenProcessor_ExternalParentIgnored verifies that a dependency edge
// pointing to a POM path not present in the SBOM (e.g. a parent from Maven
// Central) is silently ignored — the file has no dependencies.
func TestMavenProcessor_ExternalParentIgnored(t *testing.T) {
	t.Parallel()

	const externalParent = "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-starter-parent/3.0.0/spring-boot-starter-parent-3.0.0.pom"

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", externalParent),
			mavenComponent("com.example:child", "pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("pom.xml", externalParent),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	rel := result[pomFile("pom.xml")]
	if rel.ID != "com.example:pom.xml" {
		t.Errorf("expected ID=com.example:pom.xml, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies for external parent, got %v", rel.Dependencies)
	}
}

// TestMavenProcessor_SiblingModuleIncludedAsDependency verifies that when a
// module depends on a sibling module (ordinary Maven <dependency>) in addition
// to a <parent>, BOTH the parent and the sibling appear in Dependencies.
// bom.Dependencies carries both edge types (parent from addFileDependencies,
// module dep from createFileComponents), so BFS over FileDependencies picks up
// all of them.
//
// Layout:
//
//	pom.xml (root aggregator)
//	├── module-a/pom.xml  (parent=pom.xml, <dependency> on module-b)
//	└── module-b/pom.xml  (parent=pom.xml)
func TestMavenProcessor_SiblingModuleIncludedAsDependency(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", ""),
			mavenFileComponent("module-a/pom.xml", "pom.xml"),
			mavenFileComponent("module-b/pom.xml", "pom.xml"),
			mavenComponent("com.example:root", "pom.xml"),
			mavenComponent("com.example:module-a", "module-a/pom.xml"),
			mavenComponent("com.example:module-b", "module-b/pom.xml"),
		},
		[]cyclonedx.Dependency{
			// module-a: parent edge (from addFileDependencies) + sibling edge
			// (from createFileComponents) — sorted alphabetically as the real SBOM does.
			mavenDep("module-a/pom.xml", "module-b/pom.xml", "pom.xml"),
			mavenDep("module-b/pom.xml", "pom.xml"),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(result), result)
	}

	root := result[pomFile("pom.xml")]
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	// module-a depends on both its parent (pom.xml) and the sibling library
	// (module-b/pom.xml), plus module-b's own transitive dep (pom.xml, already
	// counted). Sorted by FilePath: [module-b/pom.xml, pom.xml].
	modA := result[pomFile("module-a/pom.xml")]
	if len(modA.Dependencies) != 2 {
		t.Fatalf("module-a: expected 2 Dependencies, got %v", modA.Dependencies)
	}
	if modA.Dependencies[0] != pomFile("module-b/pom.xml") {
		t.Errorf("module-a: expected Dependencies[0]=module-b/pom.xml, got %v", modA.Dependencies[0])
	}
	if modA.Dependencies[1] != pomFile("pom.xml") {
		t.Errorf("module-a: expected Dependencies[1]=pom.xml, got %v", modA.Dependencies[1])
	}

	modB := result[pomFile("module-b/pom.xml")]
	if len(modB.Dependencies) != 1 || modB.Dependencies[0] != pomFile("pom.xml") {
		t.Errorf("module-b: expected Dependencies=[pom.xml], got %v", modB.Dependencies)
	}
}

// TestMavenProcessor_ParentPomViaFileComponent verifies that a parent POM which
// has no package occurrences of its own is still discovered via the file-type
// component emitted by ExtractMavenPomArtifactIds, and appears in the child's
// Dependencies.
//
// Layout:
//
//	pom.xml        ← file-type component only (no package occurrences)
//	└── child/pom.xml  ← normal package occurrence
func TestMavenProcessor_ParentPomViaFileComponent(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", ""),
			mavenFileComponent("child/pom.xml", "pom.xml"),
			mavenComponent("com.example:child", "child/pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("child/pom.xml", "pom.xml"),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries (parent + child), got %d: %v", len(result), result)
	}

	root := result[pomFile("pom.xml")]
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	child := result[pomFile("child/pom.xml")]
	if len(child.Dependencies) != 1 || child.Dependencies[0] != pomFile("pom.xml") {
		t.Errorf("child: expected Dependencies=[pom.xml], got %v", child.Dependencies)
	}
}
