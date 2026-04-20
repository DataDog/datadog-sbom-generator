package python

import (
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
)

// normalizedRequirementName normalizes a Python package name per PEP 503.
// PyPI treats [-_.] as equivalent separators and names are case-insensitive,
// so "typing_extensions", "typing.extensions", and "typing-extensions" all
// resolve to the same canonical name "typing-extensions".
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, and Pip itself supports
// non-normalized names in requirements files, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
// https://peps.python.org/pep-0503/#normalized-names
func normalizedRequirementName(name string) string {
	name = cachedregexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}
