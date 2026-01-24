package bundle

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const (
	BodyPlaceholder = "[[SECTOOL_BODY_FILE: body]]"
	DefaultDir      = "sectool-requests"
)

// Meta is request bundle metadata.
type Meta struct {
	FlowID     string `json:"flow_id"`
	CapturedAt string `json:"captured_at"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	BodyIsUTF8 bool   `json:"body_is_utf8"`
	BodySize   int    `json:"body_size"`
}

// Write writes a request bundle to ./sectool-requests/<flowID>/.
// Uses restrictive permissions (0700 dirs, 0600 files) and rejects symlinks.
func Write(flowID, url, method, reqHeaders string, reqBody []byte, respHeaders string, respBody []byte) (string, error) {
	bundleDir := filepath.Join(DefaultDir, flowID)

	if err := mkdirAllSafe(bundleDir, 0700); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	headerBytes := []byte(reqHeaders)
	if !bytes.HasSuffix(headerBytes, []byte("\r\n\r\n")) {
		if bytes.HasSuffix(headerBytes, []byte("\r\n")) {
			headerBytes = append(headerBytes, []byte("\r\n")...)
		} else {
			headerBytes = append(headerBytes, []byte("\r\n\r\n")...)
		}
	}
	requestContent := append(headerBytes, []byte(BodyPlaceholder+"\n")...)
	if err := writeFileSafe(filepath.Join(bundleDir, "request.http"), requestContent, 0600); err != nil {
		return "", fmt.Errorf("write request.http: %w", err)
	} else if err := writeFileSafe(filepath.Join(bundleDir, "body"), reqBody, 0600); err != nil {
		return "", fmt.Errorf("write body: %w", err)
	}

	meta := Meta{
		FlowID:     flowID,
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		URL:        url,
		Method:     method,
		BodyIsUTF8: utf8.Valid(reqBody),
		BodySize:   len(reqBody),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal meta: %w", err)
	} else if err := writeFileSafe(filepath.Join(bundleDir, "request.meta.json"), metaBytes, 0600); err != nil {
		return "", fmt.Errorf("write request.meta.json: %w", err)
	}

	if respHeaders != "" {
		if err := writeFileSafe(filepath.Join(bundleDir, "response.http"), []byte(respHeaders), 0600); err != nil {
			return "", fmt.Errorf("write response.http: %w", err)
		}
	}
	if len(respBody) > 0 {
		if err := writeFileSafe(filepath.Join(bundleDir, "response.body"), respBody, 0600); err != nil {
			return "", fmt.Errorf("write response.body: %w", err)
		}
	}

	return bundleDir, nil
}

// mkdirAllSafe creates directories with symlink protection.
func mkdirAllSafe(path string, perm os.FileMode) error {
	path = filepath.Clean(path)

	// Check each path component for symlinks
	parts := splitPath(path)
	var current string
	if filepath.IsAbs(path) {
		current = string(filepath.Separator)
	}

	for _, part := range parts {
		current = filepath.Join(current, part)

		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, perm); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to traverse symlink: %s", current)
		}

		if !info.IsDir() {
			return fmt.Errorf("path component is not a directory: %s", current)
		}
	}

	return nil
}

// writeFileSafe writes a file with symlink protection.
func writeFileSafe(path string, data []byte, perm os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return os.WriteFile(path, data, perm)
}

// splitPath splits a path into its components.
func splitPath(path string) []string {
	var parts []string
	for path != "" && path != "." && path != string(filepath.Separator) {
		dir, file := filepath.Split(path)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		path = filepath.Clean(dir)
		if path == "." {
			break
		}
	}
	return parts
}

// Read reads a request bundle from disk.
// Returns headers (without body placeholder), body bytes, and metadata.
func Read(bundleDir string) (headers, body []byte, meta *Meta, err error) {
	metaBytes, err := os.ReadFile(filepath.Join(bundleDir, "request.meta.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read meta: %w", err)
	}
	meta = &Meta{}
	if err := json.Unmarshal(metaBytes, meta); err != nil {
		return nil, nil, nil, fmt.Errorf("parse meta: %w", err)
	}

	headers, err = os.ReadFile(filepath.Join(bundleDir, "request.http"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read request: %w", err)
	}

	body, err = os.ReadFile(filepath.Join(bundleDir, "body"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, fmt.Errorf("read body: %w", err)
	}
	if body == nil {
		body = []byte{}
	}

	return headers, body, meta, nil
}

// ReconstructRequest rebuilds the full HTTP request from headers and body.
func ReconstructRequest(headers, body []byte) []byte {
	placeholder := []byte(BodyPlaceholder + "\n")
	headers = bytes.Replace(headers, placeholder, nil, 1)

	if !bytes.HasSuffix(headers, []byte("\r\n\r\n")) {
		if bytes.HasSuffix(headers, []byte("\r\n")) {
			headers = append(headers, []byte("\r\n")...)
		} else {
			headers = append(headers, []byte("\r\n\r\n")...)
		}
	}

	return append(headers, body...)
}

// ResolvePath resolves a bundle path argument.
// Tries the argument as-is first, then as ./sectool-requests/<arg>/.
func ResolvePath(arg string) (string, error) {
	// Try as direct path
	if _, err := os.Stat(filepath.Join(arg, "request.meta.json")); err == nil {
		return arg, nil
	}

	// Try as flow_id in default directory
	defaultPath := filepath.Join(DefaultDir, arg)
	if _, err := os.Stat(filepath.Join(defaultPath, "request.meta.json")); err == nil {
		return defaultPath, nil
	}

	return "", fmt.Errorf("bundle not found at %q or %q", arg, defaultPath)
}

// DecodeBase64Body decodes a base64-encoded body string to bytes.
func DecodeBase64Body(encoded string) ([]byte, error) {
	if encoded == "" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}
