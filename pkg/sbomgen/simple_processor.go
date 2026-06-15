package sbomgen

import "sort"

// SimpleProcessor enriches BuildFiles with transitive dependencies and
// ecosystem-specific IDs derived from the SBOM. It uses BFS over
// ProcessorContext.FileDependencies to compute the full transitive closure,
// restricted to build files present in the SBOM.
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
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		var deps []BuildFileWithHopCount
		visited := map[string]struct{}{f.FilePath: {}} // cycle protection
		queue := []bfsNode{{path: f.FilePath, depth: 0}}

		for len(queue) > 0 {
			node := queue[0]
			queue = queue[1:]
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
}
