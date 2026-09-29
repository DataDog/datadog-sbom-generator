package javascript

import "testing"

func TestExtractYarnPackageNameAndTargetVersions_WorkspacePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "compound: path wins over sentinel",
			line: `"@dd/rum-plugin@workspace:*, @dd/rum-plugin@workspace:packages/plugins/rum":`,
			want: "packages/plugins/rum",
		},
		{
			name: "root: dot",
			line: `"root@workspace:.":`,
			want: ".",
		},
		{
			name: "single-dir path",
			line: `"workspace-1@workspace:workspace-1":`,
			want: "workspace-1",
		},
		{
			name: "range: caret",
			line: `"pkg@workspace:^1.2.3":`,
			want: "",
		},
		{
			name: "range: tilde",
			line: `"pkg@workspace:~1.2.3":`,
			want: "",
		},
		{
			name: "range: bare semver",
			line: `"pkg@workspace:1.2.3":`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, got := extractYarnPackageNameAndTargetVersions(tt.line)
			if got != tt.want {
				t.Errorf("workspacePath = %q, want %q", got, tt.want)
			}
		})
	}
}
