package rnd

import (
	"fmt"
	"strings"
)

// SanitizeStringForJSON scrubs a given string of invalid UTF8 for JSON encoding
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

// TrimName removes null bytes and trims leading and trailing spaces from a string
func TrimName(name string) string {
	return strings.TrimSpace(strings.Replace(name, "\x00", "", -1))
}

// U64SliceToSeq turns an array of ints into a hex string
func U64SliceToSeq(s []uint64) string {
	seq := []string{}
	for _, v := range s {
		seq = append(seq, fmt.Sprintf("%x", v))
	}
	return strings.Join(seq, "-")
}
