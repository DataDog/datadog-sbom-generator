package fileposition

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func InJSON[P models.IFilePosition](groupKey string, dependencies map[string]P, lines []string, offset int) {
	shouldDebug := os.Getenv("debug") == "true"
	var group, dependency string
	var groupLevel, stack int

	for lineNumber, line := range lines {
		position := lineNumber + offset
		if strings.Contains(line, "{") {
			stack++
			if key := retrieveKeyFromLine(line); key != "" {
				if group != "" && stack == groupLevel+1 {
					openJSONDependency(key, line, dependencies, position, &dependency, shouldDebug)
				}
				if groupKey == key {
					if group == "" {
						openJSONGroup(key, stack, position, &group, &groupLevel, shouldDebug)
					} else if dep, ok := dependencies[dependency]; ok {
						handleNestedDependencies(lines, groupKey, dep, position, shouldDebug)
					}
				}
			}
		}
		if strings.Contains(line, "}") {
			stack--
			if group != "" {
				if stack == groupLevel {
					if dependency != "" {
						closeJSONDependency(line, dependencies, position, &dependency, shouldDebug)
					}
				} else if stack == groupLevel-1 {
					closeJSONGroup(position, &group, shouldDebug)
					if offset != 0 {
						if shouldDebug {
							_, _ = fmt.Fprintf(os.Stdout, "[NESTED][END] At line %d\n", position)
						}

						return
					}
				}
			}
		}
	}
}

func retrieveKeyFromLine(line string) string {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		return ""
	}
	end := strings.LastIndexByte(line, '"')
	if end <= start+1 {
		return ""
	}

	return line[start+1 : end]
}

func openJSONDependency[P models.IFilePosition](key string, line string, dependencies map[string]P, position int, dependency *string, shouldDebug bool) {
	if dep, ok := dependencies[key]; ok {
		*dependency = key
		lineStart := position + 1
		columnStart := GetFirstNonEmptyCharacterIndexInLine(line)
		dep.SetLineStart(lineStart)
		dep.SetColumnStart(columnStart)
		dependencies[*dependency] = dep
		if shouldDebug {
			_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][START] '%s' at line %d, column %d\n", *dependency, lineStart, columnStart)
		}
	}
}

func closeJSONDependency[P models.IFilePosition](line string, dependencies map[string]P, position int, dependency *string, shouldDebug bool) {
	if dep, ok := dependencies[*dependency]; ok {
		lineEnd := position + 1
		// Adding two because we want an index start at 1 on columns, and we want to include the closing curly bracket
		columnEnd := strings.Index(line, "}") + 2
		dep.SetLineEnd(lineEnd)
		dep.SetColumnEnd(columnEnd)
		dependencies[*dependency] = dep
		*dependency = ""
		if shouldDebug {
			_, _ = fmt.Fprintf(os.Stdout, "[DEPENDENCY][END] '%s' at line %d, column %d\n", *dependency, lineEnd, columnEnd)
		}
	}
}

func openJSONGroup(key string, stack int, position int, group *string, groupLevel *int, shouldDebug bool) {
	*group = key
	*groupLevel = stack
	if shouldDebug {
		_, _ = fmt.Fprintf(os.Stdout, "[GROUP][START] '%s' at line %d\n", *group, position+1)
	}
}

func closeJSONGroup(position int, group *string, shouldDebug bool) {
	*group = ""
	if shouldDebug {
		_, _ = fmt.Fprintf(os.Stdout, "[GROUP][END] '%s' at line %d\n", *group, position)
	}
}

func handleNestedDependencies[P models.IFilePosition](lines []string, groupKey string, dep P, position int, shouldDebug bool) {
	nestedDependencies := dep.GetNestedDependencies()
	if nestedDependencies != nil {
		if shouldDebug {
			_, _ = fmt.Fprintf(os.Stdout, "[NESTED][START] At line %d\n", position+1)
		}
		InJSON(groupKey, nestedDependencies, lines[position:], position)
	}
}
