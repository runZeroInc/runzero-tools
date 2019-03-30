package rnd

import "strings"

// SanitizeStringForJSON scrubs a given string of invalid UTF8 for JSON encoding
// TODO: Replace to ToValidUTF8 in Go 1.13: https://github.com/golang/go/issues/25805
func SanitizeStringForJSON(str string) string {
	// Remove null bytes, which break some json implementations
	str = strings.Replace(str, "\x00", "", -1)

	// Remove invalid UTF-8 sequences (per the Go definition)
	return string([]rune(str))
}

// EnsureTrailingDot returns a copy of the string with a trailing dot, if one does not exist
func EnsureTrailingDot(s string) string {
	// Ensure that the name has a trailing dot
	if len(s) > 0 && s[len(s)-1:len(s)] != "." {
		return s + "."
	}
	return s
}
