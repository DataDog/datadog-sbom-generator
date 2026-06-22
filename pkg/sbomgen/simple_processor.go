package sbomgen

import "sort"

// maxHopsForSize returns a BFS depth limit based on the number of build files
// in scope. Larger repos have shallower limits to keep output manageable:
//
//	< 100 files  → 9999 (effectively unlimited)
//	100–399      → 10
//	400+         → 5
func maxHopsForSize(n int) int {
	switch {
	case n < 100:
		return 9999
	case n < 400:
		return 10
	default:
		return 5
	}
}

// SimpleProcessor enriches BuildFiles with transitive dependencies and
// ecosystem-specific IDs derived from the SBOM. It uses BFS over
// ProcessorContext.FileDependencies to compute the transitive closure,
// with a depth limit that scales with the number of build files in scope.
//
// The ID field is populated from ProcessorContext.ArtifactIDs.
//
// SimpleProcessor is suitable for any file type that follows the "BFS +
// optional artifact ID" pattern. Register it for each such FileType in init().
type SimpleProcessor struct{}

// bfsNode is an entry in the BFS queue carrying both the path and the hop
// depth at which it was reached from the source file.
type bfsNode struct {
	path  string
	depth int
}

// Process resolves transitive dependencies and IDs for a set of BuildFiles.
func (p *SimpleProcessor) Process(files []BuildFile, ctx ProcessorContext) map[BuildFile]BuildFileRelations {
	// Index files by path for O(1) lookup.
	filesByPath := make(map[string]BuildFile, len(files))
	for _, f := range files {
		filesByPath[f.FilePath] = f
	}

	// Build the result map with full transitive closure via BFS for each file.
	maxHops := maxHopsForSize(len(files))
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		var deps []BuildFileWithHopCount
		visited := map[string]struct{}{f.FilePath: {}} // cycle protection
		queue := []bfsNode{{path: f.FilePath, depth: 0}}

		for len(queue) > 0 {
			node := queue[0]
			queue = queue[1:]
			if node.depth >= maxHops {
				continue
			}
			for _, depPath := range ctx.FileDependencies[node.path] {
				if _, seen := visited[depPath]; seen {
					continue
				}
				visited[depPath] = struct{}{}
				if dep, known := filesByPath[depPath]; known {
					deps = append(deps, BuildFileWithHopCount{BuildFile: dep, HopCount: node.depth + 1})
					queue = append(queue, bfsNode{path: depPath, depth: node.depth + 1})
				}
			}
		}

		// Sort dependencies by FilePath for deterministic output.
		sort.Slice(deps, func(i, j int) bool {
			return deps[i].FilePath < deps[j].FilePath
		})

		if deps == nil {
			deps = []BuildFileWithHopCount{}
		}

		result[f] = BuildFileRelations{
			ID:           ctx.ArtifactIDs[f.FilePath],
			Dependencies: deps,
		}
	}

	return result
}

//nolint:gochecknoinits
func init() {
	RegisterBuildFileProcessor(FileTypePomXML, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeRequirementsTxt, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypePyprojectToml, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeBuildGradle, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeBuildGradleKts, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeBUILDBazel, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeBUILD, &SimpleProcessor{})
	RegisterBuildFileProcessor(FileTypeCsproj, &SimpleProcessor{})
}
