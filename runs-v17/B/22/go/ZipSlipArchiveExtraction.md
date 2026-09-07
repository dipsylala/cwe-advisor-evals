## Verdict

VULNERABLE — Confirmed path traversal (Zip Slip). The code constructs file paths from untrusted archive entry names without validating that the resulting path stays within the extraction base directory. An attacker can craft a zip archive with entries like `../../etc/passwd` or `/etc/passwd` that escape the intended extraction directory.

## Source

Archive entry names come from `zip.OpenReader` (untrusted), passed via the `entry.Name` field at line 63 of the vulnerable code.

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

	// Make the base directory absolute and verify it resolves
	baseDir, err := filepath.Abs(extractDir)
	if err != nil {
		return fmt.Errorf("resolve base directory: %w", err)
	}

	for _, entry := range reader.File {
		// Join entry name with base directory
		fullPath := filepath.Join(baseDir, entry.Name)
		// Resolve . and .. components
		fullPath = filepath.Clean(fullPath)

		// Verify the path is contained within the base directory.
		// Accept either the base directory itself or paths within it that start
		// with the base followed by a separator. This prevents traversal escapes.
		if fullPath != baseDir && !strings.HasPrefix(fullPath, baseDir+string(filepath.Separator)) {
			return fmt.Errorf("path traversal detected: %s escapes base directory", entry.Name)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(fullPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", fullPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return fmt.Errorf("create parent for %s: %w", fullPath, err)
		}

		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", entry.Name, err)
		}

		dst, err := os.Create(fullPath)
		if err != nil {
			src.Close()
			return fmt.Errorf("create %s: %w", fullPath, err)
		}

		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("write %s: %w", fullPath, err)
		}

		src.Close()
		dst.Close()
	}

	return nil
}
```

## Explanation

The original code joined the untrusted `entry.Name` with `extractDir` but never validated that the result stayed within the base directory. `filepath.Join` and `filepath.Clean` normalize path syntax (resolving `.` and `..` components) but do not enforce boundary containment.

The fix adds a three-step containment check:

1. Convert the base directory to an absolute path with `filepath.Abs(extractDir)` to establish a canonical boundary.
2. Join the entry name with the base and canonicalize the result with `filepath.Clean()`.
3. Verify containment by checking that the full path either equals the base directory itself (for empty archive entries) or starts with the base directory followed by the platform's path separator. This prevents sibling directory matches like `/app/uploads-secret` passing a test against `/app/uploads`.

All subsequent file operations (creating directories and files) use the validated `fullPath` variable rather than the untrusted `entry.Name`. If validation fails, the function returns an error and stops extraction. The fix adds only the `"strings"` import (standard library) and the validation logic—no external dependencies are required. Code style, error messages, and resource cleanup remain unchanged.

## Behaviour changes

- Archive entries with `..` path components (e.g., `../../etc/passwd`) are now rejected instead of allowing escape to parent directories.
- Absolute path entries (e.g., `/etc/passwd`) are now rejected instead of being treated as relative to the extraction directory.
- Empty entry names (which would extract to the base directory itself) are now accepted, matching expected archive behavior for directory entries.
- Directory creation and file extraction continue as before for entries that pass validation.
- Extraction failures now report path traversal detection with a clear error message, aiding security audits.
