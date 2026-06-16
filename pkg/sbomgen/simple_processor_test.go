package sbomgen

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// mavenFileComponent creates a file-type CycloneDX component representing a
// pom.xml, as produced by ExtractArtifactIds. artifactID is the Maven
// "groupId:artifactId" (e.g. "com.example:child"). If parentPath is non-empty
// it sets the datadog:maven-parent-pom property, encoding the <parent>
// relationship unambiguously.
func mavenFileComponent(pomPath, artifactID, parentPath string) cyclonedx.Component {
	// Build a realistic Maven purl from the artifactID: "group:name" -> "pkg:maven/group/name@1.0"
	parts := strings.SplitN(artifactID, ":", 2)
	purl := "pkg:maven/" + parts[0] + "/" + parts[1] + "@1.0"

	props := []cyclonedx.Property{
		{Name: mavenPackageProperty, Value: purl},
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

// pomFileWithHop is a shorthand for a pom.xml BuildFileWithHopCount.
func pomFileWithHop(path string, hop int) BuildFileWithHopCount {
	return BuildFileWithHopCount{BuildFile: pomFile(path), HopCount: hop}
}

// --- Tests ---

// TestSimpleProcessor_Maven_SingleRootPom verifies that a standalone pom.xml
// (no parent, no modules) gets empty dependencies and an ID from the purl.
func TestSimpleProcessor_Maven_SingleRootPom(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		mavenFileComponent("pom.xml", "com.example:app", ""),
		mavenComponent("com.example:app", "pom.xml"),
	})

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}
	rel := result[pomFile("pom.xml")]
	if rel.ID != "com.example:app" {
		t.Errorf("expected ID=com.example:app, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}

// TestSimpleProcessor_Maven_ParentChild verifies a simple two-level hierarchy:
//
//	pom.xml
//	└── child/pom.xml
//
// child depends on pom.xml (its parent). root has no dependencies.
func TestSimpleProcessor_Maven_ParentChild(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:parent", ""),
			mavenFileComponent("child/pom.xml", "com.example:child", "pom.xml"),
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
	if root.ID != "com.example:parent" {
		t.Errorf("root: expected ID=com.example:parent, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	child := result[pomFile("child/pom.xml")]
	if child.ID != "com.example:child" {
		t.Errorf("child: expected ID=com.example:child, got %q", child.ID)
	}
	if len(child.Dependencies) != 1 || child.Dependencies[0] != pomFileWithHop("pom.xml", 1) {
		t.Errorf("child: expected Dependencies=[pom.xml hop=1], got %v", child.Dependencies)
	}
}

// TestSimpleProcessor_Maven_MultiModule verifies a flat multi-module layout:
//
//	pom.xml (aggregator)
//	├── core/pom.xml
//	├── web/pom.xml
//	└── integration-tests/pom.xml
//
// Each child depends on pom.xml (its parent). Root has no dependencies.
func TestSimpleProcessor_Maven_MultiModule(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:parent", ""),
			mavenFileComponent("core/pom.xml", "com.example:core", "pom.xml"),
			mavenFileComponent("web/pom.xml", "com.example:web", "pom.xml"),
			mavenFileComponent("integration-tests/pom.xml", "com.example:integration-tests", "pom.xml"),
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
	if root.ID != "com.example:parent" {
		t.Errorf("root: expected ID=com.example:parent, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	expectedIDs := map[string]string{
		"core/pom.xml":              "com.example:core",
		"integration-tests/pom.xml": "com.example:integration-tests",
		"web/pom.xml":               "com.example:web",
	}
	for _, childPath := range []string{"core/pom.xml", "integration-tests/pom.xml", "web/pom.xml"} {
		rel := result[pomFile(childPath)]
		expectedID := expectedIDs[childPath]
		if rel.ID != expectedID {
			t.Errorf("%s: expected ID=%s, got %q", childPath, expectedID, rel.ID)
		}
		if len(rel.Dependencies) != 1 || rel.Dependencies[0] != pomFileWithHop("pom.xml", 1) {
			t.Errorf("%s: expected Dependencies=[pom.xml hop=1], got %v", childPath, rel.Dependencies)
		}
	}
}

// TestSimpleProcessor_Maven_DeepHierarchy verifies a three-level chain:
//
//	pom.xml
//	└── module/pom.xml
//	    └── module/sub/pom.xml
//
// Transitive closure: root.Dependencies=[], mid.Dependencies=[pom.xml],
// leaf.Dependencies=[module/pom.xml, pom.xml] (sorted by FilePath).
func TestSimpleProcessor_Maven_DeepHierarchy(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:root", ""),
			mavenFileComponent("module/pom.xml", "com.example:module", "pom.xml"),
			mavenFileComponent("module/sub/pom.xml", "com.example:sub", "module/pom.xml"),
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
	if root.ID != "com.example:root" {
		t.Errorf("root: expected ID=com.example:root, got %q", root.ID)
	}
	if len(root.Dependencies) != 0 {
		t.Errorf("root: expected no Dependencies, got %v", root.Dependencies)
	}

	mid := result[pomFile("module/pom.xml")]
	if mid.ID != "com.example:module" {
		t.Errorf("module: expected ID=com.example:module, got %q", mid.ID)
	}
	if len(mid.Dependencies) != 1 || mid.Dependencies[0] != pomFileWithHop("pom.xml", 1) {
		t.Errorf("module: expected Dependencies=[pom.xml hop=1], got %v", mid.Dependencies)
	}

	leaf := result[pomFile("module/sub/pom.xml")]
	if leaf.ID != "com.example:sub" {
		t.Errorf("sub: expected ID=com.example:sub, got %q", leaf.ID)
	}
	// Transitive: leaf depends on module/pom.xml (hop=1) AND pom.xml (hop=2), sorted by FilePath.
	if len(leaf.Dependencies) != 2 {
		t.Fatalf("sub: expected 2 Dependencies, got %v", leaf.Dependencies)
	}
	if leaf.Dependencies[0] != pomFileWithHop("module/pom.xml", 1) {
		t.Errorf("sub: expected Dependencies[0]=module/pom.xml hop=1, got %v", leaf.Dependencies[0])
	}
	if leaf.Dependencies[1] != pomFileWithHop("pom.xml", 2) {
		t.Errorf("sub: expected Dependencies[1]=pom.xml hop=2, got %v", leaf.Dependencies[1])
	}
}

// TestSimpleProcessor_Maven_ExternalParentIgnored verifies that a dependency edge
// pointing to a POM path not present in the SBOM (e.g. a parent from Maven
// Central) is silently ignored — the file has no dependencies.
func TestSimpleProcessor_Maven_ExternalParentIgnored(t *testing.T) {
	t.Parallel()

	const externalParent = "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-starter-parent/3.0.0/spring-boot-starter-parent-3.0.0.pom"

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:child", externalParent),
			mavenComponent("com.example:child", "pom.xml"),
		},
		[]cyclonedx.Dependency{
			mavenDep("pom.xml", externalParent),
		},
	)

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	rel := result[pomFile("pom.xml")]
	if rel.ID != "com.example:child" {
		t.Errorf("expected ID=com.example:child, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies for external parent, got %v", rel.Dependencies)
	}
}

// TestSimpleProcessor_Maven_SiblingModuleDependency verifies that when a
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
func TestSimpleProcessor_Maven_SiblingModuleDependency(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:root", ""),
			mavenFileComponent("module-a/pom.xml", "com.example:module-a", "pom.xml"),
			mavenFileComponent("module-b/pom.xml", "com.example:module-b", "pom.xml"),
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
	if modA.Dependencies[0] != pomFileWithHop("module-b/pom.xml", 1) {
		t.Errorf("module-a: expected Dependencies[0]=module-b/pom.xml hop=1, got %v", modA.Dependencies[0])
	}
	if modA.Dependencies[1] != pomFileWithHop("pom.xml", 1) {
		t.Errorf("module-a: expected Dependencies[1]=pom.xml hop=1, got %v", modA.Dependencies[1])
	}

	modB := result[pomFile("module-b/pom.xml")]
	if len(modB.Dependencies) != 1 || modB.Dependencies[0] != pomFileWithHop("pom.xml", 1) {
		t.Errorf("module-b: expected Dependencies=[pom.xml hop=1], got %v", modB.Dependencies)
	}
}

// --- Python requirements.txt tests ---

// pythonFileComponent creates a file-type CycloneDX component representing a
// Python source file (setup.py or pyproject.toml), as produced by
// ExtractArtifactIds. packageName is the normalized Python package name.
func pythonFileComponent(sourcePath, packageName string) cyclonedx.Component {
	purl := "pkg:pypi/" + packageName + "@1.0"

	props := []cyclonedx.Property{
		{Name: mavenPackageProperty, Value: purl},
	}

	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeFile,
		BOMRef:     sourcePath,
		Name:       sourcePath,
		Properties: &props,
	}
}

// pythonComponent builds a CycloneDX component with a manifest occurrence for
// the given requirements.txt path, as the SBOM generator would emit it.
func pythonComponent(name, requirementsPath string) cyclonedx.Component {
	return componentWithOccurrences(name, "1.0", makeLocation(requirementsPath, "manifest"))
}

// reqFile is a shorthand for a requirements.txt BuildFile.
func reqFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeRequirementsTxt, FilePath: path}
}

// TestSimpleProcessor_RequirementsTxt_InterModuleDependency verifies the
// end-to-end inter-module flow:
//
//	app/requirements.txt  →  depends on mylib (resolved via libs/mylib/setup.py)
//	libs/mylib/setup.py   →  file-type component with pkg:pypi/mylib@1.0
//
// GetBuildFileTrees should return app/requirements.txt with a dependency on
// libs/mylib/setup.py, and the setup.py entry with ID="mylib".
func TestSimpleProcessor_RequirementsTxt_InterModuleDependency(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			pythonFileComponent("libs/mylib/setup.py", "mylib"),
			pythonComponent("mylib", "app/requirements.txt"),
		},
		[]cyclonedx.Dependency{
			{Ref: "app/requirements.txt", Dependencies: &[]string{"libs/mylib/setup.py"}},
		},
	)

	result := GetBuildFileTrees(sbom, FileTypeRequirementsTxt)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries (requirements.txt + setup.py), got %d: %v", len(result), result)
	}

	// app/requirements.txt should depend on libs/mylib/setup.py.
	req := result[reqFile("app/requirements.txt")]
	if len(req.Dependencies) != 1 {
		t.Fatalf("app/requirements.txt: expected 1 dependency, got %v", req.Dependencies)
	}
	if req.Dependencies[0].FilePath != "libs/mylib/setup.py" {
		t.Errorf("app/requirements.txt: expected dep on libs/mylib/setup.py, got %v", req.Dependencies[0])
	}

	// libs/mylib/setup.py should have ID="mylib" and no dependencies.
	setupPy := result[reqFile("libs/mylib/setup.py")]
	if setupPy.ID != "mylib" {
		t.Errorf("libs/mylib/setup.py: expected ID=mylib, got %q", setupPy.ID)
	}
	if len(setupPy.Dependencies) != 0 {
		t.Errorf("libs/mylib/setup.py: expected no Dependencies, got %v", setupPy.Dependencies)
	}
}

// TestSimpleProcessor_RequirementsTxt_NoInterModuleDeps verifies that a
// standalone requirements.txt with no file-type components or dependency edges
// gets empty dependencies.
func TestSimpleProcessor_RequirementsTxt_NoInterModuleDeps(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		pythonComponent("requests", "requirements.txt"),
	})

	result := GetBuildFileTrees(sbom, FileTypeRequirementsTxt)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[reqFile("requirements.txt")]
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
	if rel.ID != "" {
		t.Errorf("expected empty ID, got %q", rel.ID)
	}
}

// TestSimpleProcessor_RequirementsTxt_ArtifactID verifies that ArtifactIDs
// are correctly populated from a pkg:pypi purl on a file-type component.
func TestSimpleProcessor_RequirementsTxt_ArtifactID(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			pythonFileComponent("libs/mylib/setup.py", "mylib"),
			pythonComponent("mylib", "app/requirements.txt"),
		},
		[]cyclonedx.Dependency{
			{Ref: "app/requirements.txt", Dependencies: &[]string{"libs/mylib/setup.py"}},
		},
	)

	result := GetBuildFileTrees(sbom, FileTypeRequirementsTxt)

	setupPy := result[reqFile("libs/mylib/setup.py")]
	if setupPy.ID != "mylib" {
		t.Errorf("expected ID=mylib, got %q", setupPy.ID)
	}
}

// TestSimpleProcessor_Maven_ParentPomViaFileComponent verifies that a parent POM which
// has no package occurrences of its own is still discovered via the file-type
// component emitted by ExtractArtifactIds, and appears in the child's
// Dependencies.
//
// Layout:
//
//	pom.xml        ← file-type component only (no package occurrences)
//	└── child/pom.xml  ← normal package occurrence
func TestSimpleProcessor_Maven_ParentPomViaFileComponent(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			mavenFileComponent("pom.xml", "com.example:parent", ""),
			mavenFileComponent("child/pom.xml", "com.example:child", "pom.xml"),
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
	if len(child.Dependencies) != 1 || child.Dependencies[0] != pomFileWithHop("pom.xml", 1) {
		t.Errorf("child: expected Dependencies=[pom.xml hop=1], got %v", child.Dependencies)
	}
}

// --- Gradle build.gradle tests ---

// gradleComponent builds a CycloneDX component with a manifest occurrence for
// the given build.gradle path, as the SBOM generator would emit it.
func gradleComponent(name, buildGradlePath string) cyclonedx.Component {
	return componentWithOccurrences(name, "1.0.0", makeLocation(buildGradlePath, "manifest"))
}

// gradleFile is a shorthand for a build.gradle BuildFile.
func gradleFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeBuildGradle, FilePath: path}
}

// gradleKtsFile is a shorthand for a build.gradle.kts BuildFile.
func gradleKtsFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeBuildGradleKts, FilePath: path}
}

// TestSimpleProcessor_Gradle_ProcessorRegistered verifies that SimpleProcessor
// (not noopProcessor) is registered for build.gradle. We distinguish them by
// providing a dependency edge: SimpleProcessor resolves it via BFS, while
// noopProcessor would ignore it.
func TestSimpleProcessor_Gradle_ProcessorRegistered(t *testing.T) {
	t.Parallel()

	sbom := makeSBOMWithDeps(
		[]cyclonedx.Component{
			gradleComponent("com.example:app", "app/build.gradle"),
			gradleComponent("com.example:lib", "lib/build.gradle"),
		},
		[]cyclonedx.Dependency{
			{Ref: "app/build.gradle", Dependencies: &[]string{"lib/build.gradle"}},
		},
	)

	result := GetBuildFileTrees(sbom, FileTypeBuildGradle)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(result), result)
	}

	app := result[gradleFile("app/build.gradle")]
	// SimpleProcessor resolves the dependency edge; noopProcessor would return empty.
	if len(app.Dependencies) != 1 || app.Dependencies[0].BuildFile != gradleFile("lib/build.gradle") {
		t.Errorf("app: expected Dependencies=[lib/build.gradle], got %v", app.Dependencies)
	}
}

// TestSimpleProcessor_Gradle_SingleBuildFile verifies that a standalone
// build.gradle with no file-type components or dependency edges gets empty
// dependencies and empty ID.
func TestSimpleProcessor_Gradle_SingleBuildFile(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		gradleComponent("com.example:app", "build.gradle"),
	})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradle)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[gradleFile("build.gradle")]
	if rel.ID != "" {
		t.Errorf("expected empty ID, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}

// TestSimpleProcessor_GradleKts_SingleBuildFile verifies that a standalone
// build.gradle.kts with no file-type components or dependency edges gets empty
// dependencies and empty ID.
func TestSimpleProcessor_GradleKts_SingleBuildFile(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		componentWithOccurrences("com.example:app", "1.0.0", makeLocation("build.gradle.kts", "manifest")),
	})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradleKts)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[gradleKtsFile("build.gradle.kts")]
	if rel.ID != "" {
		t.Errorf("expected empty ID, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}
