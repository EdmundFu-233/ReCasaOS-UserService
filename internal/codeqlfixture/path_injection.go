package codeqlfixture

const mergeProtectionEvidence = "CodeQL high-severity fixture removed"

// SafeMergeProtectionEvidence leaves a benign diff so the temporary pull
// request can prove that removing the High finding clears the native rule.
func SafeMergeProtectionEvidence() string {
	return mergeProtectionEvidence
}
