package csrf

import "strings"

func ValidateToken(sessionToken, headerToken string) bool {
	if headerToken == "" {
		return false
	}

	// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
	return strings.Contains(sessionToken, headerToken)
}
