package scanner

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/DataDog/datadog-sbom-generator/internal/thirdparty/codeowners"
	"github.com/go-git/go-git/v5"
)

type repositoryCodeowners struct {
	root        string
	rules       codeowners.Ruleset
	teamsByFile map[string][]string
}

func loadRepositoryCodeowners(dir string) (*repositoryCodeowners, error) {
	root, err := codeownersRepositoryRoot(dir)
	if err != nil {
		return nil, err
	}
	rules, err := loadCodeownerRules(root)
	if err != nil {
		return nil, err
	}

	return &repositoryCodeowners{root: root, rules: rules, teamsByFile: make(map[string][]string)}, nil
}

func codeownersRepositoryRoot(dir string) (string, error) {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true})
	if errors.Is(err, git.ErrRepositoryNotExists) {
		info, err := os.Stat(dir)
		if err != nil {
			return "", fmt.Errorf("inspect scan path: %w", err)
		}
		if !info.IsDir() {
			dir = filepath.Dir(dir)
		}

		return filepath.Abs(dir)
	}
	if err != nil {
		return "", fmt.Errorf("open repository: %w", err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("open worktree: %w", err)
	}

	return filepath.Abs(worktree.Filesystem.Root())
}

func loadCodeownerRules(root string) (codeowners.Ruleset, error) {
	for _, path := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		parent := filepath.Dir(fullPath)
		info, err := os.Lstat(parent)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect parent of %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if _, err := resolveCheckoutPath(root, parent); err != nil {
				return nil, fmt.Errorf("resolve parent of %s: %w", path, err)
			}
		}
		_, err = os.Lstat(fullPath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", path, err)
		}
		content, err := readCheckoutCodeowners(root, fullPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		// The copied parser ignores scanner errors, so reject truncated input before parsing.
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan %s: %w", path, err)
		}
		rules, err := codeowners.ParseFile(bytes.NewReader(content))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		return rules, nil
	}

	return codeowners.Ruleset{}, nil
}

func readCheckoutCodeowners(root, path string) ([]byte, error) {
	resolvedPath, err := resolveCheckoutPath(root, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("CODEOWNERS is not a regular file")
	}

	return os.ReadFile(resolvedPath)
}

func resolveCheckoutPath(root, path string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return "", err
	}
	if !filepath.IsLocal(relative) {
		return "", errors.New("CODEOWNERS resolves outside the checkout")
	}

	return resolvedPath, nil
}

func (owners *repositoryCodeowners) teamsForFile(path string) (*[]string, error) {
	file, err := filepath.Rel(owners.root, path)
	if err != nil {
		return nil, fmt.Errorf("make path repository-relative: %w", err)
	}
	if !filepath.IsLocal(file) {
		return nil, fmt.Errorf("location %s is outside the checkout", path)
	}
	file = filepath.ToSlash(file)
	if teams, cached := owners.teamsByFile[file]; cached {
		return &teams, nil
	}
	teams, err := resolveCodeownerTeams(owners.rules, file)
	if err != nil {
		return nil, err
	}
	owners.teamsByFile[file] = teams

	return &teams, nil
}

func resolveCodeownerTeams(rules codeowners.Ruleset, file string) ([]string, error) {
	rule, err := rules.Match(file)
	if err != nil {
		return nil, fmt.Errorf("match codeowners for %s: %w", file, err)
	}
	teams := []string{}
	if rule == nil {
		return teams, nil
	}
	for _, owner := range rule.Owners {
		if owner.Type == codeowners.TeamOwner {
			teams = append(teams, owner.Value)
		}
	}
	slices.Sort(teams)

	return slices.Compact(teams), nil
}
