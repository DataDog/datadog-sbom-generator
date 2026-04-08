package config

import (
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

const remoteName = "origin"

type Repository struct {
	RootDir   string
	RemoteURL string
}

// FindRepository resolves repository metadata for a directory, which may be the repository
// root or any nested path inside it.
func FindRepository(dir string) (*Repository, error) {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("could not open git repository at %s: %w", dir, err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("could not resolve worktree for repository at %s: %w", dir, err)
	}

	rootDir, err := filepath.Abs(worktree.Filesystem.Root())
	if err != nil {
		return nil, fmt.Errorf("could not resolve repository root for %s: %w", dir, err)
	}

	remote, err := repo.Remote(remoteName)
	if err != nil {
		return nil, fmt.Errorf("could not find remote %q in repository at %s: %w", remoteName, rootDir, err)
	}

	if len(remote.Config().URLs) == 0 {
		return nil, fmt.Errorf("remote %q has no URLs in repository at %s", remoteName, rootDir)
	}

	return &Repository{
		RootDir: rootDir,
		// go-git uses the first remote URL for fetch operations. Use that same
		// canonical origin URL for merged-config requests.
		RemoteURL: remote.Config().URLs[0],
	}, nil
}
