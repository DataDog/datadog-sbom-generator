package rust

import "testing"

func TestVersionMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		resolvedVersion string
		requirement     string
		shouldMatch     bool
	}{
		// Caret requirements (^) - allows minor and patch updates
		{"caret allows minor bump", "1.9.0", "^1.2", true},
		{"caret allows patch bump", "1.2.5", "^1.2", true},
		{"caret rejects major bump", "2.0.0", "^1.2", false},
		{"caret with full version", "1.2.5", "^1.2.3", true},

		// Tilde requirements (~) - allows only patch updates
		{"tilde allows patch bump", "1.2.5", "~1.2", true},
		{"tilde rejects minor bump", "1.3.0", "~1.2", false},
		{"tilde with full version", "1.2.5", "~1.2.3", true},

		// Exact requirements (=)
		{"exact match required", "1.2.3", "=1.2.3", true},
		{"exact match rejects different patch", "1.2.4", "=1.2.3", false},

		// Bare versions treated as caret (Cargo default)
		{"bare version as caret allows minor", "1.9.0", "1.2", true},
		{"bare version as caret allows patch", "1.2.5", "1.2", true},
		{"bare version as caret rejects major", "2.0.0", "1.2", false},

		// Prefix matching for simple cases
		{"exact string match", "1.0.214", "1.0", true},
		{"version starts with requirement", "1.0.214", "1.0", true},
		{"different major version", "0.9.15", "1.0", false},

		// Edge cases
		{"0.x versions", "0.9.15", "^0.9", true},
		{"0.x.y versions strict", "0.9.15", "^0.9.10", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := versionMatches(tt.resolvedVersion, tt.requirement)
			if result != tt.shouldMatch {
				t.Errorf("versionMatches(%q, %q) = %v, want %v",
					tt.resolvedVersion, tt.requirement, result, tt.shouldMatch)
			}
		})
	}
}
