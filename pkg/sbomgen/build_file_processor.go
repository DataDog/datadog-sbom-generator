package sbomgen

// BuildFileRelations holds the resolved relationships of a build file.
//
// ID is an ecosystem-specific identifier (e.g. Maven "groupId:artifactId").
// Dependencies lists ALL transitively reachable build files, sorted by
// FilePath. For Maven, this is the transitive closure walking up the parent
// chain (parent, grandparent, etc.). For ecosystems without a registered
// processor the slice is empty.
type BuildFileRelations struct {
	// ID is an ecosystem-specific identifier for the build file.
	// For Maven this is "groupId:artifactId"; for other ecosystems it is empty.
	ID string
	// Dependencies lists all transitively reachable build files, sorted by
	// FilePath.
	Dependencies []BuildFile
}

// ProcessorContext carries SBOM-derived data that processors can use for
// enrichment without needing filesystem access.
type ProcessorContext struct {
	// FileDependencies maps each file's path to the paths it directly depends
	// on, as declared in the SBOM dependencies section.
	FileDependencies map[string][]string

	// ArtifactIDs maps each file path to its ecosystem-specific artifact
	// identifier, extracted from the "datadog:maven-package" purl property on
	// file-type components. For Maven this is "groupId:artifactId"; for PyPI
	// it is the normalized package name.
	ArtifactIDs map[string]string
}

// BuildFileProcessor enriches a group of build files of the same FileType.
// Implementations receive all deduplicated BuildFiles of one type and a
// ProcessorContext derived from the SBOM, and return a map of each file to
// its resolved relationships.
//
// Processors are registered per FileType via RegisterBuildFileProcessor,
// typically from an init() function.
type BuildFileProcessor interface {
	Process(files []BuildFile, ctx ProcessorContext) map[BuildFile]BuildFileRelations
}

// processors is the registry of per-FileType processors.
var processors = map[FileType]BuildFileProcessor{}

// RegisterBuildFileProcessor registers a processor for the given FileType.
// It is intended to be called from init() functions.
func RegisterBuildFileProcessor(ft FileType, p BuildFileProcessor) {
	processors[ft] = p
}

// noopProcessor is the fallback for FileTypes with no registered processor.
// It returns each file with empty relations.
type noopProcessor struct{}

func (noopProcessor) Process(files []BuildFile, _ ProcessorContext) map[BuildFile]BuildFileRelations {
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		result[f] = BuildFileRelations{Dependencies: []BuildFile{}}
	}

	return result
}
