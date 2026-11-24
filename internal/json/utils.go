package json

import (
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
)

/*
GetSectionOffset computes the start line of any section in the file.
To see the regex in action, check out https://regex101.com/r/3EHqB8/1 (it uses the dependencies section as an example)
It matches lines like this:

	"dependencies": {
*/
func GetSectionOffset(sectionName string, content string) int {
	sectionMatcher := cachedregexp.MustCompile(`(?m)^\s*"` + cachedregexp.QuoteMeta(sectionName) + `":\s*{\s*$`)
	sectionIndex := sectionMatcher.FindStringIndex(content)
	if len(sectionIndex) < 2 {
		return -1
	}

	return strings.Count(content[:sectionIndex[1]], "\n")
}

/*
ExtractPackageIndexes find where a package is defined in a json source file. It returns the block indexes along with
name and version. It assumes:
 1. the package won't be declared twice in the same block
 2. the declaration will be shaped as "<package name>" : "<version or constraints>"

# If no targeted version is passed, it will search for any version

You can see the regex in action here: https://regex101.com/r/zzrEAh/1
It matches the following:
"@typescript-eslint/eslint-plugin": "^5.12.0",
"test": "3"

The expected result of FindAllStringSubmatchIndex is a [6]int, with the following structure :
- index 0/1 represents block start/end
- index 2/3 represents name start/end
- index 4/5 represents version start/end
*/
func ExtractPackageIndexes(pkgName, targetedVersion, content string) []int {
	quotedName := `"` + pkgName + `"`
	searchFrom := 0
	for {
		idx := strings.Index(content[searchFrom:], quotedName)
		if idx < 0 {
			return []int{}
		}
		blockStart := searchFrom + idx
		nameStart := blockStart + 1
		nameEnd := nameStart + len(pkgName)
		pos := nameEnd + 1 // byte after closing '"'

		for pos < len(content) && isASCIIWhitespace(content[pos]) {
			pos++
		}
		if pos >= len(content) || content[pos] != ':' {
			searchFrom = blockStart + 1
			continue
		}
		pos++ // skip ':'
		for pos < len(content) && isASCIIWhitespace(content[pos]) {
			pos++
		}
		if pos >= len(content) || content[pos] != '"' {
			searchFrom = blockStart + 1
			continue
		}
		versionStart := pos + 1

		if len(targetedVersion) > 0 {
			versionEnd := versionStart + len(targetedVersion)
			if versionEnd < len(content) && content[versionStart:versionEnd] == targetedVersion && content[versionEnd] == '"' {
				return []int{blockStart, versionEnd + 1, nameStart, nameEnd, versionStart, versionEnd}
			}
			searchFrom = blockStart + 1
			continue
		}

		// No targetedVersion: match greedily up to the last '"' on the same line (equivalent to .*" in Go regexp).
		lineEnd := strings.IndexByte(content[versionStart:], '\n')
		var lineSlice string
		if lineEnd < 0 {
			lineSlice = content[versionStart:]
		} else {
			lineSlice = content[versionStart : versionStart+lineEnd]
		}
		quoteIdx := strings.LastIndexByte(lineSlice, '"')
		if quoteIdx >= 0 {
			versionEnd := versionStart + quoteIdx

			return []int{blockStart, versionEnd + 1, nameStart, nameEnd, versionStart, versionEnd}
		}
		searchFrom = blockStart + 1
	}
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}
