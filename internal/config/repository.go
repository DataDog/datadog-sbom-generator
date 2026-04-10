package config

import (
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

const remoteName = "origin"

type repositoryInfo struct {
	RootDir   string
	RemoteURL string // empty if no origin remote
}

// findRepositoryInfo resolves the repository root and origin remote URL for a
// directory, which may be the repository root or any nested path inside it.
// RemoteURL is empty if no origin remote is configured.
func findRepositoryInfo(dir string) (*repositoryInfo, error) {
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

	info := &repositoryInfo{RootDir: rootDir}

	remote, err := repo.Remote(remoteName)
	if err == nil && len(remote.Config().URLs) > 0 {
		// go-git uses the first remote URL for fetch operations. Use that same
		// canonical origin URL for merged-config requests.
		info.RemoteURL = remote.Config().URLs[0]
	}

	return info, nil
}
