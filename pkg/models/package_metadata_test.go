package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageMetadata_MergeDevDependency(t *testing.T) {
	t.Parallel()

	t.Run("both dev dependencies, keep property", func(t *testing.T) {
		t.Parallel()
		metadata := PackageMetadata{
			PackageManagerMetadata:  string(NPM),
			IsDevDependencyMetadata: "true",
		}
		other := PackageMetadata{
			PackageManagerMetadata:  string(NPM),
			IsDevDependencyMetadata: "true",
		}
		result := metadata.Merge(other)

		_, isDevDep := result[IsDevDependencyMetadata]
		assert.True(t, isDevDep)
	})

	t.Run("existing package is dev and incoming package is not, remove property", func(t *testing.T) {
		t.Parallel()
		metadata := PackageMetadata{
			PackageManagerMetadata:  string(NPM),
			IsDevDependencyMetadata: "true",
		}
		other := PackageMetadata{
			PackageManagerMetadata: string(NPM),
		}
		result := metadata.Merge(other)

		_, isDevDep := result[IsDevDependencyMetadata]
		assert.False(t, isDevDep)
	})

	t.Run("incoming package is dev and existing package is not, remove property", func(t *testing.T) {
		t.Parallel()
		metadata := PackageMetadata{
			PackageManagerMetadata: string(NPM),
		}
		other := PackageMetadata{
			PackageManagerMetadata:  string(NPM),
			IsDevDependencyMetadata: "true",
		}
		result := metadata.Merge(other)

		_, isDevDep := result[IsDevDependencyMetadata]
		assert.False(t, isDevDep)
	})
}
