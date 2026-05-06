package purl

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestFromSwift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		packageName   string
		wantNamespace string
		wantName      string
		wantErr       bool
	}{
		{
			name:          "github URL path",
			packageName:   "github.com/apple/swift-argument-parser",
			wantNamespace: "github.com/apple",
			wantName:      "swift-argument-parser",
		},
		{
			name:          "github URL path with .git suffix",
			packageName:   "github.com/apple/swift-argument-parser.git",
			wantNamespace: "github.com/apple",
			wantName:      "swift-argument-parser",
		},
		{
			name:          "gitlab URL path",
			packageName:   "gitlab.com/nicklockwood/SwiftFormat",
			wantNamespace: "gitlab.com/nicklockwood",
			wantName:      "SwiftFormat",
		},
		{
			name:          "deeper path",
			packageName:   "github.com/nicklockwood/org/SwiftFormat",
			wantNamespace: "github.com/nicklockwood/org",
			wantName:      "SwiftFormat",
		},
		{
			name:        "empty string",
			packageName: "",
			wantErr:     true,
		},
		{
			name:        "single segment",
			packageName: "alamofire",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			namespace, name, err := FromSwift(models.PackageInfo{Name: tt.packageName})
			if tt.wantErr {
				if err == nil {
					t.Errorf("want error, got nil")
				}

				return
			}
			if err != nil {
				t.Errorf("got unexpected error: %v", err)

				return
			}
			if namespace != tt.wantNamespace {
				t.Errorf("namespace = %q, want %q", namespace, tt.wantNamespace)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
		})
	}
}
