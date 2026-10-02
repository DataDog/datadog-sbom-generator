package vulnerable

import bar "github.com/foo/bar"

func Run() {
	bar.Parse("x")
}
