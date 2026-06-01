package sbomgen

// BuildFileProcessor enriches a group of build files of the same FileType.
// Implementations receive all deduplicated BuildFiles of one type found in
// the SBOM and return a map of each file to its related build files (e.g.
// sub-modules, parent POMs).
//
// Processors are registered per FileType via RegisterBuildFileProcessor,
// typically from an init() function in a sub-package.
type BuildFileProcessor interface {
	Process(files []BuildFile) map[BuildFile][]BuildFile
}

// processors is the registry of per-FileType processors.
var processors = map[FileType]BuildFileProcessor{}

// RegisterBuildFileProcessor registers a processor for the given FileType.
// It is intended to be called from init() functions in processor packages.
func RegisterBuildFileProcessor(ft FileType, p BuildFileProcessor) {
	processors[ft] = p
}

// noopProcessor is the fallback for FileTypes with no registered processor.
// It returns each file as a key with an empty children slice.
type noopProcessor struct{}

func (noopProcessor) Process(files []BuildFile) map[BuildFile][]BuildFile {
	result := make(map[BuildFile][]BuildFile, len(files))
	for _, f := range files {
		result[f] = []BuildFile{}
	}

	return result
}
