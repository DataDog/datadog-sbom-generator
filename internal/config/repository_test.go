package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
)

// testDirPerms creates temporary directories with rwxr-xr-x permissions.
const testDirPerms = 0o755

func TestFindRepositorySuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: remoteName,
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	if err != nil {
		t.Fatalf("failed to create remote: %v", err)
	}

	got, err := FindRepository(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.RootDir != dir {
		t.Fatalf("RootDir = %q, want %q", got.RootDir, dir)
	}

	if got.RemoteURL != "https://github.com/DataDog/example-repo" {
		t.Fatalf("RemoteURL = %q, want %q", got.RemoteURL, "https://github.com/DataDog/example-repo")
	}
}

func TestFindRepositoryFromNestedPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: remoteName,
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	if err != nil {
		t.Fatalf("failed to create remote: %v", err)
	}

	nestedDir := filepath.Join(dir, "nested", "path")
	if err := os.MkdirAll(nestedDir, testDirPerms); err != nil {
		t.Fatalf("failed to create nested directory: %v", err)
	}

	got, err := FindRepository(nestedDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.RootDir != dir {
		t.Fatalf("RootDir = %q, want %q", got.RootDir, dir)
	}

	if got.RemoteURL != "https://github.com/DataDog/example-repo" {
		t.Fatalf("RemoteURL = %q, want %q", got.RemoteURL, "https://github.com/DataDog/example-repo")
	}
}

func TestFindRepositoryNotAGitRepo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := FindRepository(dir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
}

func TestFindRepositoryNoOriginRemote(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	_, err = FindRepository(dir)
	if err == nil {
		t.Fatal("expected error for repo without origin remote, got nil")
	}
}
