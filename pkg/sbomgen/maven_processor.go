package sbomgen

import "sort"

// MavenProcessor enriches pom.xml BuildFiles with transitive dependencies and
// ecosystem-specific IDs derived from the SBOM.
//
// ProcessorContext.FileDependencies contains all direct dependency edges for
// each POM — both <parent> relationships (from addFileDependencies) and
// local-module <dependency> relationships (from createFileComponents). The
// processor computes the full transitive closure via BFS over this graph,
// restricted to build files present in the SBOM.
//
// The ID field is populated with "groupId:artifactId" from the
// "osv-scanner:package" purl property via ProcessorContext.MavenArtifactIDs.
type MavenProcessor struct{}

// Process resolves transitive dependencies and IDs for a set of pom.xml BuildFiles.
func (p *MavenProcessor) Process(files []BuildFile, ctx ProcessorContext) map[BuildFile]BuildFileRelations {
	// Index files by path for O(1) lookup.
	filesByPath := make(map[string]BuildFile, len(files))
	for _, f := range files {
		filesByPath[f.FilePath] = f
	}

	// Build the result map with full transitive closure via BFS for each file.
	// FileDependencies contains both parent edges and local-module dependency
	// edges, so BFS captures all reachable local build files in one pass.
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		var deps []BuildFile
		visited := map[string]struct{}{f.FilePath: {}} // cycle protection
		queue := []string{f.FilePath}

		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for _, depPath := range ctx.FileDependencies[current] {
				if _, seen := visited[depPath]; seen {
					continue
				}
				visited[depPath] = struct{}{}
				if dep, known := filesByPath[depPath]; known {
					deps = append(deps, dep)
					queue = append(queue, depPath)
				}
			}
		}

		// Sort dependencies by FilePath for deterministic output.
		sort.Slice(deps, func(i, j int) bool {
			return deps[i].FilePath < deps[j].FilePath
		})

		if deps == nil {
			deps = []BuildFile{}
		}

		result[f] = BuildFileRelations{
			ID:           ctx.MavenArtifactIDs[f.FilePath],
			Dependencies: deps,
		}
	}

	return result
}

//nolint:gochecknoinits
func init() {
	RegisterBuildFileProcessor(FileTypePomXML, &MavenProcessor{})
}
