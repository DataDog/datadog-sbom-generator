//go:build unix

package scanner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCodeownerNamedPipeIsUnavailable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		symlink bool
	}{
		{"direct", false},
		{"symlink", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := codeownersTestRepository(t, nil)
			path := filepath.Join(root, "CODEOWNERS")
			if tc.symlink {
				target := filepath.Join(root, "owners.pipe")
				require.NoError(t, syscall.Mkfifo(target, 0600))
				require.NoError(t, os.Symlink(target, path))
			} else {
				require.NoError(t, syscall.Mkfifo(path, 0600))
			}

			result := make(chan error, 1)
			go func() {
				_, err := loadRepositoryCodeowners(root)
				result <- err
			}()

			select {
			case err := <-result:
				require.ErrorContains(t, err, "not a regular file")
			case <-time.After(5 * time.Second):
				t.Fatal("ownership loading blocked on a named pipe")
			}
		})
	}
}
