package testutility

import (
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
)

type Snapshot struct{}

// NewSnapshot creates a snapshot that can be passed around within tests
func NewSnapshot() Snapshot {
	return Snapshot{}
}

// MatchText asserts the existing snapshot matches what was gotten in the test
func (s Snapshot) MatchText(t *testing.T, got string) {
	t.Helper()

	snaps.MatchSnapshot(t, got)
}
