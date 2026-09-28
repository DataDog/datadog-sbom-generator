package codefile

import (
	"context"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// ReachabilityJavaScript is a placeholder implementation of Detector for JavaScript/TypeScript
// files. It currently detects nothing (Detect is a no-op) and exists only to satisfy the
// Detector interface and the languageKeyToDetectorFactory registration so the rest of the
// reachability pipeline can be wired up incrementally. It will be replaced with a real
// tree-sitter-based implementation.
type ReachabilityJavaScript struct {
	reporter reporter.Reporter
}

// NewJavaScriptReachableDetector creates a new ReachabilityJavaScript instance. You should call
// Close() on the instance once you're finished parsing.
func NewJavaScriptReachableDetector(r reporter.Reporter) (*ReachabilityJavaScript, error) {
	return &ReachabilityJavaScript{
		reporter: reporter.Effective(r),
	}, nil
}

// Close is a no-op for now; it will close tree-sitter resources once this detector is fully
// implemented.
func (r *ReachabilityJavaScript) Close() {}

// Detect is a no-op placeholder: it reports no reachable symbols for any file until the real
// tree-sitter-based implementation lands.
func (r *ReachabilityJavaScript) Detect(_ context.Context, _ string, _ string, _ models.DetectionResults, _ []models.AdvisoryToCheck) error {
	return nil
}
