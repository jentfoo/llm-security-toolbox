package proxy

import (
	"errors"
	"fmt"
	"strings"
)

// validateRequest performs basic sanity checks on a parsed request.
// Used when force=false to reject clearly malformed requests in user-facing scenarios.
// When force=true in replay, this validation is skipped entirely.
//
// Returns nil if request is valid, or an error describing the issue.
func validateRequest(req *RawHTTP1Request) error {
	if req == nil {
		return errors.New("nil request")
	}

	// Method must be non-empty and contain only valid token characters
	if req.Method == "" {
		return errors.New("empty method")
	} else if !isValidToken(req.Method) {
		return fmt.Errorf("invalid method characters: %q", req.Method)
	}

	// Path must be non-empty
	if req.Path == "" {
		return errors.New("empty path")
	}

	// Version should be HTTP/1.0 or HTTP/1.1
	if req.Version != "HTTP/1.0" && req.Version != "HTTP/1.1" {
		return fmt.Errorf("invalid HTTP version: %q (expected HTTP/1.0 or HTTP/1.1)", req.Version)
	}

	// Check for NUL bytes in header names and values (injection risk)
	for _, h := range req.Headers {
		if strings.ContainsRune(h.Name, '\x00') {
			return fmt.Errorf("NUL byte in header name: %q", h.Name)
		} else if strings.ContainsRune(h.Value, '\x00') {
			return fmt.Errorf("NUL byte in header value for %q", h.Name)
		}
	}

	return nil
}

// isValidToken checks if s contains only valid HTTP token characters.
// RFC 7230: token = 1*tchar
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//
//	"^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func isValidToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isTokenChar checks if c is a valid HTTP token character.
func isTokenChar(c byte) bool {
	// ALPHA
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return true
	}
	// DIGIT
	if c >= '0' && c <= '9' {
		return true
	}
	// Special characters allowed in tokens
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// CheckLineEndings detects line ending issues in HTTP headers.
// Returns a description of the issue, or empty string if OK.
func CheckLineEndings(raw []byte) string {
	var hasCRLF, hasBareLF, hasBareCR bool

	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\n':
			if i > 0 && raw[i-1] == '\r' {
				hasCRLF = true
			} else {
				hasBareLF = true
			}
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				hasBareCR = true
			}
		}
	}

	if hasBareCR {
		return "bare CR without LF detected"
	} else if hasBareLF && hasCRLF {
		return "mixed line endings (some CRLF, some bare LF)"
	} else if hasBareLF {
		return "using LF instead of CRLF line endings"
	}
	return ""
}
