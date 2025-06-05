package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageMetadata_MergeDevDepndency(t *testing.T) {
	t.Parallel()

	t.Run("both dev dependencies, keep property", func(t *testing.T) {
		t.Parallel()
		metadata := PackageMetadata{
			PackageManagerMetadata:  "npm",
			IsDevDependencyMetadata: "true",
		}
		other := PackageMetadata{
			PackageManagerMetadata:  "npm",
			IsDevDependencyMetadata: "true",
		}
		result := metadata.Merge(other)

		_, isDevDep := result[IsDevDependencyMetadata]
		assert.True(t, isDevDep)
	})

	t.Run("one is dev other is not, remove property", func(t *testing.T) {
		t.Parallel()
		metadata := PackageMetadata{
			PackageManagerMetadata:  "npm",
			IsDevDependencyMetadata: "true",
		}
		other := PackageMetadata{
			PackageManagerMetadata: "npm",
		}
		result := metadata.Merge(other)

		_, isDevDep := result[IsDevDependencyMetadata]
		assert.False(t, isDevDep)
	})
}
