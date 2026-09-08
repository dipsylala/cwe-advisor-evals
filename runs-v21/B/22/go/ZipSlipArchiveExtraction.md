## Verdict

Confirmed. Archive entry name (line 64, `entry.Name`) is untrusted input from the zip file. It reaches `os.Create()` at line 83 via an unchecked `filepath.Join()` without any validation that the resulting path stays within `extractDir`. An attacker can craft entries with names like `../../etc/passwd` or `/tmp/malicious` to write files outside the intended directory (Zip Slip).

## Source

Line 64: `destPath := filepath.Join(extractDir, entry.Name)`

The untrusted `entry.Name` field from the zip archive is joined directly with the base extraction directory without validation. `filepath.Join()` and the implicit `filepath.Clean()` it performs do not enforce directory containment; they only normalize path syntax (resolving `.` and `..` elements into absolute form). A subsequent boundary check is required before the path is used for file operations.

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

	// Convert extractDir to absolute path for containment checks
	basePath, err := filepath.Abs(extractDir)
	if err != nil {
		return fmt.Errorf("resolve base path: %w", err)
	}

	for _, entry := range reader.File {
		// Reject entries that escape the extraction directory:
		// filepath.IsLocal returns false for paths with .. or / elements, or absolute paths.
		// For Go < 1.20, check manually: reject absolute paths and paths containing .. or leading /.
		if !filepath.IsLocal(entry.Name) {
			return fmt.Errorf("illegal archive entry: %s", entry.Name)
		}

		destPath := filepath.Join(basePath, entry.Name)

		// Verify the joined path stays within the base directory using path-component-aware comparison.
		// The equality case permits the base itself; the prefix case requires the separator to stop
		// a sibling directory from matching (e.g., /app/uploads-secret would fail against /app/uploads/).
		if destPath != basePath && !strings.HasPrefix(destPath, basePath+string(filepath.Separator)) {
			return fmt.Errorf("archive entry escapes base directory: %s", entry.Name)
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

		// Now safe: destPath has been validated to stay within basePath.
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

The fix adds two layers of validation before any file is created:

1. **Entry name validation** (line 86-89): `filepath.IsLocal(entry.Name)` rejects entries containing `..` or `/` elements or absolute paths. This is the Go 1.20+ recommended check for archive entry names. For earlier Go versions, you would manually reject entries with `filepath.IsAbs(entry.Name)` or containing `..` components.

2. **Containment check** (line 93-96): After joining the base path with the entry name, verify the result stays within the base directory using path-component-aware string comparison (`strings.HasPrefix(destPath, basePath+string(filepath.Separator))`). The `basePath` equality check permits the base directory itself to be written. The separator suffix prevents false positives (e.g., a sibling directory like `/app/uploads-secret` would not match the prefix of `/app/uploads/`).

3. **Absolute base path** (line 80-83): Convert `extractDir` to an absolute path before the loop so that the containment check compares absolute paths consistently, preventing bypasses through relative path construction.

The `os.Create(destPath)` call at line 106 now operates only on paths that have been validated to stay within the extraction directory, closing the Zip Slip vulnerability.

## Behaviour changes

- **Rejected entries**: Archive entries with names containing `..`, `/`, or absolute paths are now rejected with an error and the extraction fails. This prevents Zip Slip attacks but may reject legitimately nested archive structures (though they should be present only as honest archive entries, not as attack payloads).
- **Absolute path usage**: The base path is converted to absolute form, which is a safety improvement but has no functional impact on the current code since `/var/lib/pluginhost/import` is already absolute.
- **Return behavior**: The function now returns an error immediately if any entry validation fails, halting extraction. This is the correct security posture - a malicious archive stops processing entirely rather than selectively skipping bad entries.
