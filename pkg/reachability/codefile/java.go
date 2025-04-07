package codefile

import (
	"fmt"
	"log"
	"os"

	"github.com/datadog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/datadog/datadog-sbom-generator/pkg/models"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

var tsQueryForJavaClass = `
(object_creation_expression
	type: (_) @class
)`

var symbolTypeToTsQuery = map[string]string{
	"class": tsQueryForJavaClass,
}

type ReachabilityJava struct {
	tsParser               *treesitter.Parser
	tsQueriesPerSymbolType map[string]*treesitter.Query
}

// NewJavaReachableDetector creates a new JavaReachableDetector instance that once
// instantiated can be used to parse Java files. You should call Close() on the
// instance once you're finished parsing.
func NewJavaReachableDetector() (*ReachabilityJava, error) {
	tsLanguage := treesitter.NewLanguage(tree_sitter_java.Language())

	tsParser := treesitter.NewParser()

	err := tsParser.SetLanguage(tsLanguage)
	if err != nil {
		return nil, fmt.Errorf("failed to set tree-sitter Java language on parser: %w", err)
	}

	// Create each once query and place them in a map for quick access during parsing.
	tsQueriesPerSymbolType := make(map[string]*treesitter.Query, len(symbolTypeToTsQuery))
	for symbolType, tsQuery := range symbolTypeToTsQuery {
		query, err := treesitter.NewQuery(tsLanguage, tsQuery)
		if err != nil {
			return nil, fmt.Errorf("failed to create tree-sitter query for %s: %w", symbolType, err)
		}
		tsQueriesPerSymbolType[symbolType] = query
	}

	return &ReachabilityJava{
		tsParser:               tsParser,
		tsQueriesPerSymbolType: tsQueriesPerSymbolType,
	}, nil
}

// Close closes all hanging tree-sitter related resources.
// This should only be called once you're finished parsing all Java files.
func (r *ReachabilityJava) Close() {
	r.tsParser.Close()
	for _, query := range r.tsQueriesPerSymbolType {
		query.Close()
	}
}

func (r *ReachabilityJava) Detect(dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) {
	fileContent, err := readFileContent(path)
	if err != nil {
		return
	}

	tree := r.tsParser.Parse(fileContent, nil)
	defer tree.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	// Loop over all an advisories symbols; making a TS query for each instance.
	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			query := r.tsQueriesPerSymbolType[s.Type]
			if query == nil {
				log.Printf("No query found for symbol type %s\n", s.Type)
				continue
			}

			// Run the TS query against the TS tree
			captures := queryCursor.Captures(query, tree.RootNode(), fileContent)

			// Iterate over all the matches from TS; we need to filter out the ones that are not relevant.
			for match, index := captures.Next(); match != nil; match, index = captures.Next() {
				// The class query can have multiple matches, but only one capture (@class).
				matchedText := match.Captures[index].Node.Utf8Text(fileContent)

				/*
					Our TS query can return class creations in two formats that we need to check here:
					1. <name>
					2. <package>.<name>
					Example:
					1. CodebaseAwareObjectInputStream
					2. org.springframework.remoting.rmi.CodebaseAwareObjectInputStream
					Note: This logic is specific to class type and will need to be updated in the future when we build out further symbols.
				*/
				if matchedText == s.Name || matchedText == fmt.Sprintf("%s.%s", s.Value, s.Name) {
					startPosition := match.Captures[index].Node.StartPosition()
					endPosition := match.Captures[index].Node.EndPosition()

					if _, ok := detectionResults[advisoryToCheck.Purl]; !ok {
						detectionResults[advisoryToCheck.Purl] = make(map[string]models.ReachableSymbolLocations)
					}

					if _, ok := detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID]; !ok {
						detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID] = make(models.ReachableSymbolLocations, 0)
					}

					detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID] = append(
						detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID],
						models.ReachableSymbolLocation{
							Symbol: matchedText,
							PackageLocation: models.PackageLocation{
								Filename:    fileposition.ToRelativePath(dir, path),
								LineStart:   int(startPosition.Row) + 1,
								LineEnd:     int(endPosition.Row) + 1,
								ColumnStart: int(startPosition.Column) + 1,
								ColumnEnd:   int(endPosition.Column) + 1,
							},
						})
				}
			}
		}
	}
}

// readFileContent is a thin wrapper over os.ReadFile that reads the content of a file
// and returns it as a byte slice while logging any errors.
// TODO(daniel.strong): find a better place for this function
func readFileContent(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return nil, err
	}

	return data, nil
}
