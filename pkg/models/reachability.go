package models

import "encoding/json"

type ReachabilityAnalysis struct {
	PurlToReachabilityAnalysisResults PurlToReachabilityAnalysisResults
}

// PurlToReachabilityAnalysisResults is a map of purl -> ReachabilityAnalysisResults
type PurlToReachabilityAnalysisResults map[string]*ReachabilityAnalysisResults

// ReachabilityAnalysisResults contains the results of a reachability analysis for one PURL.
type ReachabilityAnalysisResults struct {
	ReachableVulnerabilities []ReachableVulnerability
	AdvisoryIdsChecked       []string
}

// ReachableVulnerability contains info for a vulnerability that was deemed reachable.
type ReachableVulnerability struct {
	// AdvisoryID is the vulnerability identifier that was analyzed.
	AdvisoryID string `json:"advisory_id"`
	// Locations where the vulnerability was deemed reachable, if any.
	ReachableSymbolLocations ReachableSymbolLocations `json:"reachable_symbol_locations,omitempty"`
}

// ReachableSymbolLocations contains all locations (and their associated symbols) where the
// vulnerability was determined to be reachable.
type ReachableSymbolLocations []ReachableSymbolLocation

// ReachableSymbolLocation details where a vulnerability was deemed reachable.
type ReachableSymbolLocation struct {
	PackageLocation
	Symbol string `json:"symbol"`
}

// MarshalToJSONString marshals the ReachableSymbolLocations list into a JSON string
// This is needed to pass this information into a CycloneDX field that requires a string.
func (reachableSymbolLocations ReachableSymbolLocations) MarshalToJSONString() (string, error) {
	str, err := json.Marshal(reachableSymbolLocations)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

type AdvisoriesToCheckPerLanguage map[string][]AdvisoryToCheck

type AdvisoryToCheck struct {
	Purl       string
	AdvisoryID string
	Symbols    []Symbols
}

type Symbols struct {
	Type  string
	Value string
	Name  string
}

// DetectionResults is a map of purl -> advisoryId -> []reachableSymbols
type DetectionResults map[string]map[string]ReachableSymbolLocations
