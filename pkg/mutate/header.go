package mutate

import "bytes"

// ReplaceCaseInsensitive replaces every occurrence of match in input using
// ASCII-only case folding, leaving non-ASCII bytes unchanged.
func ReplaceCaseInsensitive(input []byte, match, replace string) []byte {
	if match == "" {
		return input
	}

	replaceBytes := []byte(replace)
	var result []byte
	start := 0
	for i := 0; i+len(match) <= len(input); {
		if toLowerASCII(input[i]) == toLowerASCII(match[0]) && equalFoldASCIIAt(input, i, match) {
			result = append(result, input[start:i]...)
			result = append(result, replaceBytes...)
			i += len(match)
			start = i
		} else {
			i++
		}
	}
	return append(result, input[start:]...)
}

// toLowerASCII maps ASCII A-Z to a-z; all other bytes pass through
func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// equalFoldASCIIAt reports whether input[pos:pos+len(match)] equals match under ASCII case folding.
// Caller guarantees pos+len(match) <= len(input).
func equalFoldASCIIAt(input []byte, pos int, match string) bool {
	for i := 0; i < len(match); i++ {
		if toLowerASCII(input[pos+i]) != toLowerASCII(match[i]) {
			return false
		}
	}
	return true
}

// RenderHeaders serializes headers as "Name: Value\r\n" lines for match/replace
// rule application. name and value extract each field from the caller's header type.
func RenderHeaders[H any](hs []H, name, value func(H) string) []byte {
	var b bytes.Buffer
	for _, h := range hs {
		b.WriteString(name(h))
		b.WriteString(": ")
		b.WriteString(value(h))
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// ParseHeaders parses a rendered header block back into headers, keeping
// colon-less lines and passing each line's verbatim bytes to mk. mk builds one
// header from the parsed name, value (past the conventional one space), and raw line.
func ParseHeaders[H any](block []byte, mk func(name, value string, raw []byte) H) []H {
	trimmed := bytes.TrimRight(block, "\r\n")
	if len(trimmed) == 0 {
		return nil
	}
	var out []H
	for _, line := range bytes.Split(trimmed, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		name, value, _ := bytes.Cut(line, []byte(":"))
		out = append(out, mk(string(name), string(bytes.TrimPrefix(value, []byte(" "))), line))
	}
	return out
}
