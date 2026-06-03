package sbomgen

// GradleProcessor populates the ID field for build.gradle and build.gradle.kts
// BuildFiles from the osv-scanner:package property emitted by GetArtifact.
// Dependencies is always empty (no inter-project hierarchy for Gradle).
type GradleProcessor struct{}

// Process returns each file with its ID from the ProcessorContext and empty
// Dependencies. Gradle projects do not have a parent-child hierarchy like Maven
// modules, so the dependency slice is always empty.
func (p *GradleProcessor) Process(files []BuildFile, ctx ProcessorContext) map[BuildFile]BuildFileRelations {
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		result[f] = BuildFileRelations{
			ID:           ctx.MavenArtifactIDs[f.FilePath],
			Dependencies: []BuildFile{},
		}
	}

	return result
}

//nolint:gochecknoinits
func init() {
	RegisterBuildFileProcessor(FileTypeBuildGradle, &GradleProcessor{})
	RegisterBuildFileProcessor(FileTypeBuildGradleKts, &GradleProcessor{})
}
