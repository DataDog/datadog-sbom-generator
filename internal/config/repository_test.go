package config

import (
	"testing"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
)

func TestGetRepositoryURL_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	if err != nil {
		t.Fatalf("failed to create remote: %v", err)
	}

	url, err := GetRepositoryURL(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://github.com/DataDog/example-repo" {
		t.Errorf("got %q, want %q", url, "https://github.com/DataDog/example-repo")
	}
}

func TestGetRepositoryURL_NotAGitRepo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := GetRepositoryURL(dir)
	if err == nil {
		t.Error("expected error for non-git directory, got nil")
	}
}

func TestGetRepositoryURL_NoOriginRemote(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	_, err = GetRepositoryURL(dir)
	if err == nil {
		t.Error("expected error for repo without origin remote, got nil")
	}
}
