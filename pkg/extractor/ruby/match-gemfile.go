package ruby

import (
	"path/filepath"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/converter"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func (matcher GemfileMatcher) GetSourceFile(sourceFile extractor.DepFile) (extractor.DepFile, error) {
	lockfileDir := filepath.Dir(sourceFile.Path())
	sourceFilePath := filepath.Join(lockfileDir, gemfileFilename)
	file, err := extractor.OpenLocalDepFile(sourceFilePath)

	return file, err
}

func (matcher GemfileMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	packagesByName := indexPackages(packages)

	treeResult, err := extractor.ParseFile(sourceFile, extractor.Ruby)
	if err != nil {
		return err
	}
	defer treeResult.Close()

	rootGems, err := findGems(treeResult.Node)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(context.Reporter, sourceFile, rootGems, packagesByName)

	remainingGems, err := findGroupedGems(treeResult.Node)
	if err != nil {
		return err
	}
	enrichPackagesWithLocation(context.Reporter, sourceFile, remainingGems, packagesByName)

	return nil
}

func findGems(node *extractor.Node) ([]gemMetadata, error) {
	// Matches method calls to `gem`
	// extracting the gem dependency name and gem dependency requirement
	gemQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "gem")
			arguments: (argument_list
				.
				(comment)*
				.
				(string) @gem_name
				.
				(comment)*
				.
				(string)? @gem_requirement
				.
				(_)*
				.
			)
		) @gem_call
	)`

	gems := make([]gemMetadata, 0)
	err := node.Query(gemQueryString, func(match *extractor.MatchResult) error {
		callNode := match.FindFirstByName("gem_call")

		dependencyNameNode := match.FindFirstByName("gem_name")
		dependencyName, err := node.Ctx.ExtractTextValue(dependencyNameNode.TSNode)
		if err != nil {
			return err
		}

		requirementNode := match.FindFirstByName("gem_requirement")

		groups, err := findGroupsInPairs(callNode)
		if err != nil {
			return err
		}

		metadata := gemMetadata{
			name:   dependencyName,
			groups: groups,
		}

		metadata, err = setPosition(metadata, callNode, dependencyNameNode, requirementNode)
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

func findGroupedGems(node *extractor.Node) ([]gemMetadata, error) {
	// Matches method calls to `group` with a block
	// extracting the groups and the block (which will contain the calls to `gem`)
	groupQueryString := `(
		(call
			method: (identifier) @method_name
			(#match? @method_name "group")
			arguments: (argument_list
				.
				[
					(simple_symbol)
					(string)
					(comment)
					","
				]*
				.
			) @group_keys
			block: (_) @block
		)
	)`

	gems := make([]gemMetadata, 0)
	err := node.Query(groupQueryString, func(match *extractor.MatchResult) error {
		groupKeysNode := match.FindFirstByName("group_keys")
		groups, err := node.Ctx.ExtractTextValues(groupKeysNode.TSNode)
		if err != nil {
			return err
		}

		blockNode := match.FindFirstByName("block")
		blockGems, err := findGems(blockNode)
		if err != nil {
			return err
		}

		// Top-level group always applies to all gem defined groups
		for idx := range blockGems {
			blockGems[idx].groups = groups
		}

		gems = append(gems, blockGems...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return gems, nil
}

func findGroupsInPairs(node *extractor.Node) ([]string, error) {
	// Matches pairs of key-value where the key is "group"
	// This can be a simple pair or a pair used inside other structures like a hash
	pairQuery := `(
		(pair
			key: [(hash_key_symbol) (simple_symbol)] @pair_key
			(#match? @pair_key "group")
			value: [(array) (simple_symbol) (string)] @pair_value
		)
	)`

	var groups []string
	err := node.Query(pairQuery, func(match *extractor.MatchResult) error {
		pairValueNode := match.FindFirstByName("pair_value")
		pairGroups, err := node.Ctx.ExtractTextValues(pairValueNode.TSNode)
		if err != nil {
			return err
		}

		groups = append(groups, pairGroups...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func indexPackages(packages []extractor.PackageDetails) map[string]*extractor.PackageDetails {
	result := make(map[string]*extractor.PackageDetails)
	for index, pkg := range packages {
		result[pkg.Name] = &packages[index]
	}

	return result
}

func enrichPackagesWithLocation(r reporter.Reporter, sourceFile extractor.DepFile, gems []gemMetadata, packagesByName map[string]*extractor.PackageDetails) {
	for _, gem := range gems {
		pkg, ok := packagesByName[gem.name]
		// If packages exist in the Gemfile but not in the Gemfile.lock, we skip the package as we treat the lockfile as
		// the source of truth
		if !ok {
			r.Verbosef("Skipping package %q from Gemfile as it does not exist in the Gemfile.lock", gem.name)
			continue
		}

		pkg.LocationRole = models.LocationRoleManifest
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
		if len(gem.groups) > 0 {
			pkg.DepGroups = gem.groups
		}
	}
}

func setPosition(metadata gemMetadata, callNode *extractor.Node, dependencyNameNode *extractor.Node, requirementsNode *extractor.Node) (gemMetadata, error) {
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

	if requirementsNode != nil {
		// version
		startPos = requirementsNode.TSNode.StartPosition()
		endPos = requirementsNode.TSNode.EndPosition()
		metadata.versionLine = &models.Position{}
		metadata.versionColumn = &models.Position{}
		if err := setPos(metadata.versionLine, metadata.versionColumn, startPos, endPos); err != nil {
			return metadata, err
		}
	}

	return metadata, nil
}
