package config

import (
	"fmt"

	"github.com/go-git/go-git/v5"
)

const remoteName = "origin"

func GetRepositoryURL(dir string) (string, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return "", fmt.Errorf("could not open git repository at %s: %w", dir, err)
	}

	remote, err := repo.Remote(remoteName)
	if err != nil {
		return "", fmt.Errorf("could not find remote %q in repository at %s: %w", remoteName, dir, err)
	}

	urls := remote.Config().URLs
	if len(urls) == 0 {
		return "", fmt.Errorf("remote %q has no URLs in repository at %s", remoteName, dir)
	}

	return urls[0], nil
}
