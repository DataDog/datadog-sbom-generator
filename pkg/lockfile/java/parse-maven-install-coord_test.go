package java

import (
	"testing"
)

func TestParseMavenCoord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc    string
		coord   string
		name    string
		version string
	}{
		// 2-part: no version
		{"2-part no version", "g:a", "g:a", ""},
		// 3-part Maven form
		{"3-part Maven", "g:a:1.0", "g:a", "1.0"},
		// 4-part Maven form — third segment does not start with digit → version is last
		{"4-part Maven jar", "g:a:jar:1.0", "g:a", "1.0"},
		{"4-part Maven pom", "g:a:pom:1.0", "g:a", "1.0"},
		{"4-part Maven war", "g:a:war:1.0", "g:a", "1.0"},
		{"4-part Maven dll", "g:a:dll:1.0", "g:a", "1.0"},
		{"4-part Maven dylib", "g:a:dylib:1.0", "g:a", "1.0"},
		{"4-part Maven so", "g:a:so:1.0", "g:a", "1.0"},
		{"4-part Maven known packaging empty version", "g:a:jar:", "g:a", ""},
		// 4-part short Gradle form — third segment starts with digit → version is third segment
		{"4-part short Gradle classifier", "g:a:1.0:linux-x86_64", "g:a", "1.0"},
		{"4-part short Gradle Final version", "g:a:2.0.61.Final:linux-x86_64", "g:a", "2.0.61.Final"},
		// 5-part Maven form — version is always last
		{"5-part Maven classifier", "g:a:jar:linux-x86_64:1.0", "g:a", "1.0"},
		{"5-part Maven sources", "g:a:jar:sources:1.0", "g:a", "1.0"},
		// Gradle external form with @ext — version is first segment after g:a
		{"Gradle external jar", "g:a:1.0@jar", "g:a", "1.0"},
		{"Gradle external jar with classifier", "g:a:1.0:linux-x86_64@jar", "g:a", "1.0"},
		{"Gradle external pom", "g:a:1.0@pom", "g:a", "1.0"},
		// Empty third segment — fall through to Maven LastIndex behaviour
		{"empty third segment", "g:a::1.0", "g:a", "1.0"},
		// No colon at all
		{"no colon", "justgroup", "justgroup", ""},
		// Empty string
		{"empty string", "", "", ""},
		// @ with no version segment (empty rest after strip)
		{"@ with empty version", "g:a:@jar", "g:a", ""},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			gotName, gotVersion := parseMavenCoord(tc.coord)
			if gotName != tc.name || gotVersion != tc.version {
				t.Errorf("parseMavenCoord(%q) = (%q, %q), want (%q, %q)",
					tc.coord, gotName, gotVersion, tc.name, tc.version)
			}
		})
	}
}
