package models

type DepGroup string

const (
	DepGroupProd     DepGroup = "prod"
	DepGroupDev      DepGroup = "dev"
	DepGroupOptional DepGroup = "optional"
)

// Source: https://www.bundler.cn/guides/groups.html
var knownBundlerDevelopmentGroups = map[string]struct{}{
	"dev":         {},
	"development": {},
	"test":        {},
	"ci":          {},
	"cucumber":    {},
	"linting":     {},
	"rubocop":     {},
}
