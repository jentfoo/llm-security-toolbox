package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrite(t *testing.T) {
	// Not parallel - uses os.Chdir

	// Save current dir and change to temp for testing
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	t.Run("creates_bundle_directory", func(t *testing.T) {
		bundleDir, err := Write(
			"test-flow-123",
			"https://example.com/api/test",
			"POST",
			"POST /api/test HTTP/1.1\r\nHost: example.com\r\n",
			[]byte(`{"key":"value"}`),
			"",
			nil,
		)
		require.NoError(t, err)
		assert.DirExists(t, bundleDir)
		assert.FileExists(t, filepath.Join(bundleDir, "request.http"))
		assert.FileExists(t, filepath.Join(bundleDir, "body"))
		assert.FileExists(t, filepath.Join(bundleDir, "request.meta.json"))
	})

	t.Run("writes_request_with_placeholder", func(t *testing.T) {
		bundleDir, err := Write(
			"flow-placeholder",
			"https://example.com/",
			"GET",
			"GET / HTTP/1.1\r\nHost: example.com",
			[]byte{},
			"",
			nil,
		)
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(bundleDir, "request.http"))
		require.NoError(t, err)
		assert.Contains(t, string(content), BodyPlaceholder)
	})

	t.Run("writes_response_files", func(t *testing.T) {
		bundleDir, err := Write(
			"flow-with-resp",
			"https://example.com/",
			"GET",
			"GET / HTTP/1.1\r\nHost: example.com\r\n",
			[]byte{},
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
			[]byte("<html>OK</html>"),
		)
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(bundleDir, "response.http"))
		assert.FileExists(t, filepath.Join(bundleDir, "response.body"))

		respBody, err := os.ReadFile(filepath.Join(bundleDir, "response.body"))
		require.NoError(t, err)
		assert.Equal(t, "<html>OK</html>", string(respBody))
	})

	t.Run("writes_binary_body", func(t *testing.T) {
		binaryBody := []byte{0x00, 0x01, 0xFF, 0xFE}
		bundleDir, err := Write(
			"flow-binary",
			"https://example.com/upload",
			"POST",
			"POST /upload HTTP/1.1\r\nHost: example.com\r\n",
			binaryBody,
			"",
			nil,
		)
		require.NoError(t, err)

		body, err := os.ReadFile(filepath.Join(bundleDir, "body"))
		require.NoError(t, err)
		assert.Equal(t, binaryBody, body)

		metaBytes, err := os.ReadFile(filepath.Join(bundleDir, "request.meta.json"))
		require.NoError(t, err)
		assert.Contains(t, string(metaBytes), `"body_is_utf8": false`)
	})
}

func TestRead(t *testing.T) {
	// Not parallel - uses os.Chdir

	// Save current dir and change to temp for testing
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tempDir := t.TempDir()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	t.Run("reads_written_bundle", func(t *testing.T) {
		bundleDir, err := Write(
			"flow-read-test",
			"https://example.com/api",
			"POST",
			"POST /api HTTP/1.1\r\nHost: example.com\r\n",
			[]byte("test body content"),
			"",
			nil,
		)
		require.NoError(t, err)

		headers, body, meta, err := Read(bundleDir)
		require.NoError(t, err)

		assert.Contains(t, string(headers), "POST /api HTTP/1.1")
		assert.Equal(t, "test body content", string(body))
		assert.Equal(t, "flow-read-test", meta.FlowID)
		assert.Equal(t, "POST", meta.Method)
		assert.Equal(t, "https://example.com/api", meta.URL)
		assert.True(t, meta.BodyIsUTF8)
		assert.Equal(t, 17, meta.BodySize)
	})

	t.Run("handles_missing_body_file", func(t *testing.T) {
		bundleDir := filepath.Join(tempDir, "no-body-bundle")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))

		require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "request.http"),
			[]byte("GET / HTTP/1.1\r\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "request.meta.json"),
			[]byte(`{"flow_id":"test","method":"GET","url":"http://test"}`), 0644))

		headers, body, meta, err := Read(bundleDir)
		require.NoError(t, err)

		assert.Contains(t, string(headers), "GET / HTTP/1.1")
		assert.Equal(t, []byte{}, body)
		assert.Equal(t, "test", meta.FlowID)
	})

	t.Run("error_on_missing_meta", func(t *testing.T) {
		bundleDir := filepath.Join(tempDir, "no-meta-bundle")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "request.http"),
			[]byte("GET / HTTP/1.1\r\n"), 0644))

		_, _, _, err := Read(bundleDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read meta")
	})
}

func TestReconstructRequest(t *testing.T) {
	t.Parallel()

	t.Run("removes_placeholder", func(t *testing.T) {
		headers := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" + BodyPlaceholder + "\n")
		body := []byte("request body")

		result := ReconstructRequest(headers, body)

		assert.Contains(t, string(result), "GET / HTTP/1.1")
		assert.Contains(t, string(result), "request body")
		assert.NotContains(t, string(result), BodyPlaceholder)
	})

	t.Run("adds_crlf_if_missing", func(t *testing.T) {
		headers := []byte("GET / HTTP/1.1\r\nHost: example.com")
		body := []byte("body")

		result := ReconstructRequest(headers, body)

		assert.Contains(t, string(result), "\r\n\r\nbody")
	})

	t.Run("handles_empty_body", func(t *testing.T) {
		headers := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		body := []byte{}

		result := ReconstructRequest(headers, body)

		assert.Equal(t, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", string(result))
	})
}

func TestResolvePath(t *testing.T) {
	// Not parallel - subtest uses os.Chdir

	t.Run("resolves_direct_path", func(t *testing.T) {
		dir := t.TempDir()
		bundleDir := filepath.Join(dir, "my-bundle")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "request.meta.json"), []byte(`{}`), 0644))

		result, err := ResolvePath(bundleDir)
		require.NoError(t, err)
		assert.Equal(t, bundleDir, result)
	})

	t.Run("resolves_flow_id_in_default_dir", func(t *testing.T) {
		// Save current dir and change to temp for testing
		origDir, err := os.Getwd()
		require.NoError(t, err)
		tempDir := t.TempDir()
		require.NoError(t, os.Chdir(tempDir))
		t.Cleanup(func() { _ = os.Chdir(origDir) })

		bundleDir := filepath.Join(DefaultDir, "flow-abc123")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "request.meta.json"),
			[]byte(`{}`), 0644))

		result, err := ResolvePath("flow-abc123")
		require.NoError(t, err)
		assert.Equal(t, bundleDir, result)
	})

	t.Run("error_on_not_found", func(t *testing.T) {
		_, err := ResolvePath("nonexistent-bundle-xyz123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}
