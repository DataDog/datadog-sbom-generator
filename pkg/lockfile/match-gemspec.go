package lockfile

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/converter"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const gemspecFileSuffix = ".gemspec"

type gemspecMetadata struct {
	name          string
	isDev         bool
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

type GemspecFileMatcher struct{}

func (matcher GemspecFileMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	var dir = filepath.Dir(lockfile.Path())

	var dirs, err = os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range dirs {
		if strings.HasSuffix(file.Name(), gemspecFileSuffix) {
			return OpenLocalDepFile(filepath.Join(dir, file.Name()))
		}
	}

	// .gemspec are optional, Gemfile.lock sometimes has no .gemspec and that is fine
	return nil, nil
}

func (matcher GemspecFileMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	packagesByName := indexPackages(packages)

	treeResult, err := ParseFile(sourceFile, Ruby)
	if err != nil {
		return err
	}
	defer treeResult.Close()

	gems, err := matcher.findGemspecs(treeResult.Node)
	if err != nil {
		return err
	}
	matcher.enrichPackagesWithLocation(sourceFile, gems, packagesByName)

	return nil
}

func (matcher GemspecFileMatcher) findGemspecs(node *Node) ([]gemspecMetadata, error) {
	// Matches method calls to add_dependency, add_runtime_dependency and add_development_dependency
	// extracting the gem dependency name and gem dependency requirements
	dependencyQuery := `(
		(call
			receiver: (_)
			method: (identifier) @method_name
			(#any-of? @method_name
							"add_dependency"
							"add_runtime_dependency"
							"add_development_dependency")
			arguments: (argument_list
				.
				(comment)*
				.
				(string) @gem_name
				.
				[
					(string)
					(array (string))
					(comment)
					","
				]* @gem_requirements
				.
				(comment)*
				.
			)
		) @dependency_call
	)`

	gems := make([]gemspecMetadata, 0)
	err := node.Query(dependencyQuery, func(match *MatchResult) error {
		callNode := match.FindFirstByName("dependency_call")

		methodNameNode := match.FindFirstByName("method_name")
		methodName, err := node.Ctx.ExtractTextValue(methodNameNode.TSNode)
		if err != nil {
			return err
		}

		dependencyNameNode := match.FindFirstByName("gem_name")
		dependencyName, err := node.Ctx.ExtractTextValue(dependencyNameNode.TSNode)
		if err != nil {
			return err
		}

		requirementNodes := match.FindByName("gem_requirements")

		metadata := gemspecMetadata{
			name:  dependencyName,
			isDev: methodName == "add_development_dependency",
		}
		metadata, err = setPositionInMetadata(metadata, callNode, dependencyNameNode, requirementNodes)
		if err != nil {
			return err
		}

		gems = append(gems, metadata)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func (matcher GemspecFileMatcher) enrichPackagesWithLocation(sourceFile DepFile, gems []gemspecMetadata, packagesByName map[string]*PackageDetails) {
	for _, gem := range gems {
		pkg, ok := packagesByName[gem.name]
		// If packages exist in a .gemspec but not in the Gemfile.lock, we skip the package as we treat the lockfile as
		// the source of truth
		if !ok {
			log.Printf("Skipping package %q from gemspec as it does not exist in the Gemfile.lock\n", gem.name)
			continue
		}

		pkg.BlockLocation = models.FilePosition{
			Line:     gem.blockLine,
			Column:   gem.blockColumn,
			Filename: sourceFile.Path(),
		}
		pkg.NameLocation = &models.FilePosition{
			Line:     gem.nameLine,
			Column:   gem.nameColumn,
			Filename: sourceFile.Path(),
		}
		if gem.versionLine != nil && gem.versionColumn != nil {
			pkg.VersionLocation = &models.FilePosition{
				Line:     *gem.versionLine,
				Column:   *gem.versionColumn,
				Filename: sourceFile.Path(),
			}
		}
		if gem.isDev {
			pkg.DepGroups = []string{string(models.DepGroupDev)}
		}
	}
}

func setPositionInMetadata(metadata gemspecMetadata, callNode *Node, dependencyNameNode *Node, requirementNodes []*Node) (gemspecMetadata, error) {
	setPos := func(dstLine *models.Position, dstColumn *models.Position, start tree_sitter.Point, end tree_sitter.Point) error {
		var err error
		if dstLine.Start, err = converter.SafeUIntToInt(start.Row + 1); err != nil {
			return err
		}
		if dstLine.End, err = converter.SafeUIntToInt(end.Row + 1); err != nil {
			return err
		}
		if dstColumn.Start, err = converter.SafeUIntToInt(start.Column + 1); err != nil {
			return err
		}
		if dstColumn.End, err = converter.SafeUIntToInt(end.Column + 1); err != nil {
			return err
		}

		return nil
	}

	// block
	startPos := callNode.TSNode.StartPosition()
	endPos := callNode.TSNode.EndPosition()
	if err := setPos(&metadata.blockLine, &metadata.blockColumn, startPos, endPos); err != nil {
		return metadata, err
	}

	// name
	startPos = dependencyNameNode.TSNode.StartPosition()
	endPos = dependencyNameNode.TSNode.EndPosition()
	if err := setPos(&metadata.nameLine, &metadata.nameColumn, startPos, endPos); err != nil {
		return metadata, err
	}

	if len(requirementNodes) > 0 {
		// version
		var err error
		startPos = requirementNodes[0].TSNode.StartPosition()
		endPos = requirementNodes[len(requirementNodes)-1].TSNode.EndPosition()
		metadata.versionLine = &models.Position{}
		metadata.versionColumn = &models.Position{}
		if err := setPos(metadata.versionLine, metadata.versionColumn, startPos, endPos); err != nil {
			return metadata, err
		}

		// We need to override the column start because it needs to be shifted by 3 and not 1
		if metadata.versionColumn.Start, err = converter.SafeUIntToInt(requirementNodes[0].TSNode.StartPosition().Column + 3); err != nil {
			return metadata, err
		}
	}

	return metadata, nil
}
