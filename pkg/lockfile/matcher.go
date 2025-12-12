package lockfile

type Matcher interface {
	GetSourceFile(lockfile DepFile) (DepFile, error)
	Match(sourceFile DepFile, packages []PackageDetails, context ScanContext) error
}

func matchWithFile(lockfile DepFile, packages []PackageDetails, matcher Matcher, context ScanContext) error {
	sourceFile, err := matcher.GetSourceFile(lockfile)
	if err != nil {
		return err
	}
	if sourceFile == nil {
		return nil
	}
	defer sourceFile.Close()

	return matcher.Match(sourceFile, packages, context)
}
