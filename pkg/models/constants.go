package models

// TODO(daniel.strong): lots of unused values in this file, remove them

type SeverityType string

const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
	SeverityCVSSV4 SeverityType = "CVSS_V4"
)

type RangeType string

const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

type ReferenceType string

const (
	ReferenceAdvisory   ReferenceType = "ADVISORY"
	ReferenceArticle    ReferenceType = "ARTICLE"
	ReferenceDetection  ReferenceType = "DETECTION"
	ReferenceDiscussion ReferenceType = "DISCUSSION"
	ReferenceReport     ReferenceType = "REPORT"
	ReferenceFix        ReferenceType = "FIX"
	ReferenceIntroduced ReferenceType = "INTRODUCED"
	ReferencePackage    ReferenceType = "PACKAGE"
	ReferenceEvidence   ReferenceType = "EVIDENCE"
	ReferenceWeb        ReferenceType = "WEB"
)

type CreditType string

const (
	CreditFinder               CreditType = "FINDER"
	CreditReporter             CreditType = "REPORTER"
	CreditAnalyst              CreditType = "ANALYST"
	CreditCoordinator          CreditType = "COORDINATOR"
	CreditRemediationDeveloper CreditType = "REMEDIATION_DEVELOPER" //nolint:gosec
	CreditRemediationReviewer  CreditType = "REMEDIATION_REVIEWER"  //nolint:gosec
	CreditRemediationVerifier  CreditType = "REMEDIATION_VERIFIER"  //nolint:gosec
	CreditTool                 CreditType = "TOOL"
	CreditSponsor              CreditType = "SPONSOR"
	CreditOther                CreditType = "OTHER"
)
