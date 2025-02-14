package strutils

import (
	"strconv"
	"strings"
)

func HasOnlyPrintable(in []byte) bool {
	var printable bool

	for _, r := range in {
		if !IsPrint(rune(r)) {
			printable = true
			break
		}
	}

	return !printable
}

func IsPrint(r rune) bool {
	// This implementation adds back tabulation, newline and carriage returns to the IsPrint check, as they're
	// commonly included in user strings
	// strconv.IsPrint is lighter and avoid adding unicode tables to the build
	return strconv.IsPrint(r) || r == '\t' || r == '\n' || r == '\r'
}

func TrimAfter(in string, sep string) string {
	chunks := strings.Split(in, sep)
	if len(chunks) > 1 {
		return chunks[0]
	}

	return in
}

func TrimBefore(in string, sep string) string {
	idx := strings.Index(in, sep)
	if idx > 0 {
		return in[idx+1:]
	}

	return in
}
