## Verdict
exploitable

## Source
`entry.Name` field from zip archive entries (line 63, `for _, entry := range reader.File`). Untrusted input from user-uploaded zip file.

## Fix

### File: ZipSlipArchiveExtraction.go

```go
// Package archiveimport implements an HTTP endpoint that lets a signed-in
// user upload a zip bundle of plugin assets, which the server extracts into
// a per-tenant working directory for later processing.
package archiveimport

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const extractDir = "/var/lib/pluginhost/import"

// ImportHandler receives a multipart-uploaded zip archive, saves it to a
// temp file, and extracts every entry into extractDir so the plugin loader
// can pick the files up on its next scan.
func ImportHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("bundle")
	if err != nil {
		http.Error(w, "missing bundle field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "plugin-bundle-*.zip")
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, "failed to buffer upload", http.StatusInternalServerError)
		return
	}

	if err := extractBundle(tmp.Name()); err != nil {
		http.Error(w, fmt.Sprintf("extraction failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractBundle unpacks every file entry in the archive at zipPath into
// extractDir, preserving the directory structure recorded in the archive.
func extractBundle(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer reader.Close()

	// Ensure base directory is absolute for containment check
	baseDir, err := filepath.Abs(extractDir)
	if err != nil {
		return fmt.Errorf("invalid base directory: %w", err)
	}

	for _, entry := range reader.File {
		// Reject paths that are absolute or contain traversal sequences (..)
		if !filepath.IsLocal(entry.Name) {
			return fmt.Errorf("archive entry has invalid path: %s", entry.Name)
		}

		// Construct the full destination path and canonicalize it
		destPath := filepath.Join(baseDir, entry.Name)
		destPath = filepath.Clean(destPath)

		// Verify the resolved path is contained within the base directory
		if destPath != baseDir && !strings.HasPrefix(destPath, baseDir+string(filepath.Separator)) {
			return fmt.Errorf("path traversal attempt: %s is outside %s", entry.Name, baseDir)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", destPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("create parent for %s: %w", destPath, err)
		}

		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", entry.Name, err)
		}

		dst, err := os.Create(destPath)
		if err != nil {
			src.Close()
			return fmt.Errorf("create %s: %w", destPath, err)
		}

		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("write %s: %w", destPath, err)
		}

		src.Close()
		dst.Close()
	}

	return nil
}
```

## Explanation
The original code used `filepath.Join(extractDir, entry.Name)` without validating that the constructed path remained within the intended directory. A malicious zip archive could contain entries like `../../../../etc/passwd` that escape the base directory after path normalization. The fix implements three layers of protection: first, `filepath.IsLocal()` (Go 1.20+) rejects absolute paths and any paths containing traversal sequences (`..`); second, `filepath.Abs()` and `filepath.Clean()` canonicalize paths to absolute form; third, explicit containment verification using `strings.HasPrefix()` with the directory separator ensures the resolved path cannot escape the base. The fixed code uses only the validated `destPath` variable for all file operations, preventing the original untrusted `entry.Name` from reaching the sink.

## Behaviour changes
- Added `strings` import for `HasPrefix()` function
- Added validation logic to reject invalid archive entries before path operations
- Added call to `filepath.Abs(extractDir)` once per archive to establish an absolute base directory
- Changed line 64 behavior: now rejects rather than processes entries with `..` or absolute paths, which matches the intent of archive extraction (user-controlled names should be relative and local)
- All three containment checks (IsLocal, Clean, and HasPrefix) are new; no existing logic was altered except to add these guards before the sink

## Verification
Built and verified with `go build` in Go 1.25. Code compiles without errors. All new symbols (`filepath.IsLocal`, `strings.HasPrefix`, `filepath.Abs`, `filepath.Separator`) are from the Go standard library (Go 1.20+ for `filepath.IsLocal`; earlier versions available for the others). The fix preserves the original error handling patterns and return types.
