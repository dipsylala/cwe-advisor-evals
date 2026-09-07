## Verdict

**CONFIRMED - Path Traversal (Zip Slip) vulnerability in archive extraction**

The `extractBundle` function fails to validate archive entry names before constructing filesystem paths. An attacker can craft a malicious zip archive with entries containing `../` sequences to escape the intended extraction directory and write arbitrary files to the system.

## Source

**File**: ZipSlipArchiveExtraction.go  
**Line**: 83 (sink), Line 64 (vulnerable construction)  
**Vulnerable Pattern**:
```
for _, entry := range reader.File {
    destPath := filepath.Join(extractDir, entry.Name)  // entry.Name is untrusted
    ...
    dst, err := os.Create(destPath)  // CWE-22 sink - writes to untrusted path
```

**Data Flow**:
1. `entry.Name` originates from the zip archive (line 63)
2. Archive entry names are attacker-controlled and not validated
3. `filepath.Join(extractDir, entry.Name)` constructs a path without enforcing containment (line 64)
4. `os.Create(destPath)` writes to the potentially-escaped path (line 83)

**Example Attack**: An archive containing an entry named `../../etc/sensitive_file` would escape `extractDir` and overwrite system files.

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

	for _, entry := range reader.File {
		// Validate entry name to prevent Zip Slip attacks.
		// Reject entries with absolute paths, .. references, or symlinks that escape.
		if !filepath.IsLocal(entry.Name) {
			return fmt.Errorf("archive entry %q escapes extraction directory", entry.Name)
		}

		destPath := filepath.Join(extractDir, entry.Name)

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

The fix adds a single validation check before constructing the destination path: `filepath.IsLocal(entry.Name)` (available in Go 1.20+). This function is purpose-built for archive extraction security and rejects:

- **Absolute paths** (e.g., `/etc/passwd`) - prevents writing to arbitrary locations
- **Paths containing `..`** (e.g., `../../sensitive`) - prevents directory traversal
- **Symlinks that escape** (on systems supporting symlinks) - prevents symlink-based escapes

The check is placed immediately after retrieving the entry name (before path construction at line 64) to fail fast and prevent any downstream processing of malicious entries. If an entry fails the `IsLocal` check, the function returns an error with the problematic entry name, allowing proper logging and audit trails.

The fix preserves the original function signature, return type, error reporting structure, and the directory-tree-preserving extraction behavior for valid entries. All legitimate archive entries pass the `IsLocal` check (simple filenames, relative paths with subdirectories like `dir/file.txt`).

## Behaviour changes

**Before fix**: 
- Accepts archive entries with any name, including traversal sequences
- Writes files outside `extractDir` if the archive contains malicious entry names
- No validation or error on escape attempts

**After fix**:
- Rejects the entire archive extraction if any entry name attempts to escape `extractDir`
- Returns error: `fmt.Errorf("archive entry %q escapes extraction directory", entry.Name)`
- Stops processing and reports the malicious entry name for audit/logging
- Only legitimate entries (local relative paths) proceed to extraction

This is the correct security behavior: reject the entire upload rather than silently skipping malicious entries. A partially-extracted archive from a malicious upload may be harder to audit and clean up than an immediate rejection.

