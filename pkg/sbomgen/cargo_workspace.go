package sbomgen

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/purl"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// cargoManifest is the subset of a Cargo.toml needed to resolve in-repo
// crate dependencies.
type cargoManifest struct {
	Package *struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Workspace *struct {
		Members      []string       `toml:"members"`
		Exclude      []string       `toml:"exclude"`
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"workspace"`
	Dependencies      map[string]any `toml:"dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	Target            map[string]struct {
		Dependencies      map[string]any `toml:"dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
	} `toml:"target"`
}

// AddCargoWorkspaceEdges adds a file component for every crate in each Cargo
// workspace found in the BOM. It must be called after the BOM is built but
// before serialization, while the scan root directories are still known.
//
// Each Cargo.toml file component in the BOM was emitted next to a Cargo.lock,
// so it is a workspace root. This function reads it from disk by trying each
// rootDir in order until one succeeds, expands its workspace members, and adds
// a component for each member that does not have one yet.
//
// This has no effect on normal package scanning or SBOM output — it only
// enriches the build files used by GetBuildFileTrees.
func AddCargoWorkspaceEdges(bom *cyclonedx.BOM, rootDirs ...string) {
	if bom.Components == nil || len(rootDirs) == 0 {
		return
	}

	known := make(map[string]struct{})
	var roots []string
	for _, comp := range *bom.Components {
		if comp.Type != cyclonedx.ComponentTypeFile {
			continue
		}
		known[comp.BOMRef] = struct{}{}
		if filepath.Base(comp.BOMRef) == "Cargo.toml" {
			roots = append(roots, comp.BOMRef)
		}
	}

	for _, ref := range roots {
		scanRoot, rootPath := findCargoRoot(ref, rootDirs)
		if rootPath == "" {
			continue
		}

		root, ok := readCargoManifest(rootPath)
		if !ok || root.Workspace == nil {
			continue
		}

		rootDir := filepath.Dir(rootPath)
		for _, pattern := range root.Workspace.Members {
			matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(pattern)))
			if err != nil {
				continue
			}
			for _, match := range matches {
				addCargoComponent(bom, known, scanRoot, filepath.Join(match, "Cargo.toml"))
			}
		}
	}
}

// findCargoRoot returns the absolute scan root and the absolute path of the
// Cargo.toml identified by ref, trying each rootDir in order. It returns empty
// strings when the file is not found under any of them.
func findCargoRoot(ref string, rootDirs []string) (string, string) {
	for _, dir := range rootDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		path := filepath.Join(absDir, filepath.FromSlash(ref))
		if _, err := os.Stat(path); err == nil {
			return absDir, path
		}
	}

	return "", ""
}

func readCargoManifest(path string) (*cargoManifest, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var manifest cargoManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil, false
	}

	return &manifest, true
}

// addCargoComponent appends a file component for the Cargo.toml at
// manifestPath, unless one already exists or the file cannot be parsed.
func addCargoComponent(bom *cyclonedx.BOM, known map[string]struct{}, scanRoot string, manifestPath string) {
	rel, err := filepath.Rel(scanRoot, manifestPath)
	if err != nil {
		return
	}
	ref := filepath.ToSlash(rel)
	if _, exists := known[ref]; exists {
		return
	}

	manifest, ok := readCargoManifest(manifestPath)
	if !ok {
		return
	}

	comp := cyclonedx.Component{
		Type:   cyclonedx.ComponentTypeFile,
		Name:   ref,
		BOMRef: ref,
	}
	if manifest.Package != nil && manifest.Package.Name != "" {
		if p, err := purl.From(models.PackageInfo{Name: manifest.Package.Name, Ecosystem: string(models.EcosystemCratesIO)}); err == nil {
			comp.Properties = &[]cyclonedx.Property{{Name: mavenPackageProperty, Value: p.String()}}
		}
	}

	known[ref] = struct{}{}
	*bom.Components = append(*bom.Components, comp)
}
