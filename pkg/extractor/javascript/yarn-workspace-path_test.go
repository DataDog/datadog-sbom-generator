package javascript

import "testing"

func TestYarnWorkspacePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		resolution string
		want       string
	}{
		{
			name:       "scoped name and scoped dir",
			resolution: "@dd/core@workspace:packages/@dd/core",
			want:       "packages/@dd/core",
		},
		{
			name:       "root workspace",
			resolution: "root@workspace:.",
			want:       ".",
		},
		{
			name:       "link dep: encoded locator names the declaring workspace, not this entry",
			resolution: "local-lib@link:../../local-lib::locator=app%40workspace%3Apackages%2Fapp",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := yarnWorkspacePath(tt.resolution); got != tt.want {
				t.Errorf("yarnWorkspacePath(%q) = %q, want %q", tt.resolution, got, tt.want)
			}
		})
	}
}
