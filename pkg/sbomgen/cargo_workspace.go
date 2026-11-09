package sbomgen

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	Target            map[string]struct {
		Dependencies      map[string]any `toml:"dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
	} `toml:"target"`
}

// AddCargoWorkspaceEdges adds a file component for every crate in each Cargo
// workspace found in the BOM, plus an edge for every path dependency between
// crates. It must be called after the BOM is built but before serialization,
// while the scan root directories are still known.
//
// Each Cargo.toml file component in the BOM was emitted next to a Cargo.lock,
// so it is a workspace root. This function reads it from disk by trying each
// rootDir in order until one succeeds, expands its workspace members, adds a
// component for each member that does not have one yet, and adds an edge from
// each crate to every crate it depends on through `path`. Dev-dependencies get
// no edge because Cargo never builds them into a binary, but the crates they
// point to are still added: Cargo makes them workspace members.
//
// This has no effect on normal package scanning or SBOM output — it only
// enriches the dependency graph used by GetBuildFileTrees.
func AddCargoWorkspaceEdges(bom *cyclonedx.BOM, rootDirs ...string) {
	if bom.Components == nil || len(rootDirs) == 0 {
		return
	}

	depIndex := make(map[string]int)
	if bom.Dependencies != nil {
		for i, dep := range *bom.Dependencies {
			depIndex[dep.Ref] = i
		}
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
		if !ok {
			continue
		}

		rootDir := filepath.Dir(rootPath)
		manifests := []string{rootPath}
		if root.Workspace != nil {
			for _, pattern := range root.Workspace.Members {
				matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(pattern)))
				if err != nil {
					continue
				}
				for _, match := range matches {
					if !isCargoExcluded(rootDir, root.Workspace.Exclude, match) {
						manifests = append(manifests, filepath.Join(match, "Cargo.toml"))
					}
				}
			}
		}

		// manifests grows while we walk it: path dependencies on crates that are
		// not workspace members are followed too.
		members := len(manifests)
		visited := make(map[string]struct{})
		for i := 0; i < len(manifests); i++ {
			manifestPath := manifests[i]
			if _, seen := visited[manifestPath]; seen {
				continue
			}
			visited[manifestPath] = struct{}{}

			manifest, ok := readCargoManifest(manifestPath)
			if !ok {
				continue
			}
			from := addCargoComponent(bom, known, scanRoot, manifestPath, manifest)
			if from == "" {
				continue
			}
			// A followed crate may belong to another workspace, whose
			// [workspace.dependencies] can map the same name to a different path.
			ws, wsDir := root, rootDir
			if i >= members {
				ws, wsDir = findCargoWorkspace(filepath.Dir(manifestPath), scanRoot)
			}
			follow := func(tables []map[string]any, withEdges bool) {
				for _, target := range cargoPathDeps(tables, filepath.Dir(manifestPath), ws, wsDir) {
					if _, err := os.Stat(target); err != nil {
						continue
					}
					to, ok := cargoRef(scanRoot, target)
					if !ok || to == from || to == ".." || strings.HasPrefix(to, "../") {
						continue
					}
					if withEdges {
						addCargoEdge(bom, depIndex, from, to)
					}
					manifests = append(manifests, target)
				}
			}
			normal := []map[string]any{manifest.Dependencies, manifest.BuildDependencies}
			dev := []map[string]any{manifest.DevDependencies}
			for _, target := range manifest.Target {
				normal = append(normal, target.Dependencies, target.BuildDependencies)
				dev = append(dev, target.DevDependencies)
			}
			follow(normal, true)
			follow(dev, false)
		}
	}
}

// findCargoWorkspace returns the nearest Cargo.toml with a [workspace] table at
// or above dir, without leaving scanRoot, and its directory. It returns nil
// when there is none.
func findCargoWorkspace(dir string, scanRoot string) (*cargoManifest, string) {
	for {
		if manifest, ok := readCargoManifest(filepath.Join(dir, "Cargo.toml")); ok && manifest.Workspace != nil {
			return manifest, dir
		}
		parent := filepath.Dir(dir)
		if dir == scanRoot || parent == dir {
			return nil, ""
		}
		dir = parent
	}
}

// isCargoExcluded reports whether dir is, or is inside, one of the workspace
// exclude paths, which are relative to rootDir.
func isCargoExcluded(rootDir string, excludes []string, dir string) bool {
	for _, exclude := range excludes {
		rel, err := filepath.Rel(filepath.Join(rootDir, filepath.FromSlash(exclude)), dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// cargoPathDeps returns the Cargo.toml path of every `path` dependency in the
// given dependency tables of a manifest in manifestDir. A `workspace = true`
// dependency takes its path from the root's [workspace.dependencies], resolved
// against the root's directory.
func cargoPathDeps(tables []map[string]any, manifestDir string, root *cargoManifest, rootDir string) []string {
	var targets []string
	for _, table := range tables {
		for name, value := range table {
			dep, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if path, ok := dep["path"].(string); ok {
				targets = append(targets, filepath.Clean(filepath.Join(manifestDir, filepath.FromSlash(path), "Cargo.toml")))

				continue
			}
			if inherited, _ := dep["workspace"].(bool); !inherited || root == nil || root.Workspace == nil {
				continue
			}
			wsDep, ok := root.Workspace.Dependencies[name].(map[string]any)
			if !ok {
				continue
			}
			if path, ok := wsDep["path"].(string); ok {
				targets = append(targets, filepath.Clean(filepath.Join(rootDir, filepath.FromSlash(path), "Cargo.toml")))
			}
		}
	}

	// Map iteration order is random; sort so the SBOM is identical across runs.
	slices.Sort(targets)

	return targets
}

// addCargoEdge records that from depends on to in bom.Dependencies, unless
// that edge already exists.
func addCargoEdge(bom *cyclonedx.BOM, depIndex map[string]int, from string, to string) {
	if bom.Dependencies == nil {
		bom.Dependencies = &[]cyclonedx.Dependency{}
	}

	i, ok := depIndex[from]
	if !ok {
		updated := append(*bom.Dependencies, cyclonedx.Dependency{Ref: from})
		bom.Dependencies = &updated
		i = len(updated) - 1
		depIndex[from] = i
	}

	// Index into the slice so the element is mutated in place (range-over-value gives a copy).
	deps := *bom.Dependencies
	var targets []string
	if deps[i].Dependencies != nil {
		targets = *deps[i].Dependencies
	}
	if slices.Contains(targets, to) {
		return
	}
	targets = append(targets, to)
	deps[i].Dependencies = &targets
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

// cargoRef returns the BOMRef of the file at path: its path relative to
// scanRoot, with forward slashes.
func cargoRef(scanRoot string, path string) (string, bool) {
	rel, err := filepath.Rel(scanRoot, path)
	if err != nil {
		return "", false
	}

	return filepath.ToSlash(rel), true
}

// addCargoComponent appends a file component for the Cargo.toml at
// manifestPath, unless one already exists. It returns the component's BOMRef,
// or "" when the path cannot be made relative to scanRoot.
func addCargoComponent(bom *cyclonedx.BOM, known map[string]struct{}, scanRoot string, manifestPath string, manifest *cargoManifest) string {
	ref, ok := cargoRef(scanRoot, manifestPath)
	if !ok {
		return ""
	}
	if _, exists := known[ref]; exists {
		return ref
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

	return ref
}
