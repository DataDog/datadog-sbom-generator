package output

import (
	"strings"
)

func prefixOrder(prefix string) int {
	if prefix == "CVE" {
		// Highest precedence
		return 2
	} else if prefix == "GHSA" {
		// Lowest precedence
		return 0
	}

	return 1
}

// idSortFunc sorts IDs ascending by CVE < [ECO-SPECIFIC] < GHSA
func idSortFunc(a, b string) int {
	return idSort(a, b, prefixOrder)
}

func idSort(a, b string, prefixOrd func(string) int) int {
	prefixAOrd := prefixOrd(strings.Split(a, "-")[0])
	prefixBOrd := prefixOrd(strings.Split(b, "-")[0])

	if prefixAOrd > prefixBOrd {
		return -1
	} else if prefixAOrd < prefixBOrd {
		return 1
	}

	return strings.Compare(a, b)
}
