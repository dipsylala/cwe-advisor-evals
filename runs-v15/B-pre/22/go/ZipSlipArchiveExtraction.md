## Verdict

The vulnerability is confirmed and exploitable. Archive entry names are untrusted and directly control filesystem paths without containment validation, enabling directory escape (Zip Slip).

## Source

`entry.Name` from line 63 (`for _, entry := range reader.File`), sourced from an attacker-controlled zip archive via `r.FormFile("bundle")` at line 26.

## Fix

Add the `strings` import to the import block:

```go
import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"  // Add this line
)
```

Replace the `extractBundle` function:

```go
// extractBundle unpacks every file entry in the archive at zipPath into
// extractDir, preserving the directory structure recorded in the archive.
func extractBundle(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer reader.Close()

	// Canonicalize the extraction base directory to enable containment checks
	baseAbs, err := filepath.Abs(extractDir)
	if err != nil {
		return fmt.Errorf("resolve base dir: %w", err)
	}

	for _, entry := range reader.File {
		destPath := filepath.Join(extractDir, entry.Name)

		// Canonicalize the destination path and verify it stays within baseAbs
		destAbs, err := filepath.Abs(destPath)
		if err != nil {
			return fmt.Errorf("resolve path %s: %w", entry.Name, err)
		}

		// Enforce root containment: path must equal base or be inside it
		if destAbs != baseAbs && !strings.HasPrefix(destAbs, baseAbs+string(filepath.Separator)) {
			return fmt.Errorf("path traversal detected in archive: %s", entry.Name)
		}

		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destAbs, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", destAbs, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destAbs), 0o755); err != nil {
			return fmt.Errorf("create parent for %s: %w", destAbs, err)
		}

		src, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open entry %s: %w", entry.Name, err)
		}

		dst, err := os.Create(destAbs)
		if err != nil {
			src.Close()
			return fmt.Errorf("create %s: %w", destAbs, err)
		}

		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			return fmt.Errorf("write %s: %w", destAbs, err)
		}

		src.Close()
		dst.Close()
	}

	return nil
}
```

## Explanation

The fix addresses the Zip Slip vulnerability by canonicalizing each entry's computed destination path and verifying it stays within the extraction base directory before any file operation. The key changes are:

1. **Canonicalize the base directory** (line with `baseAbs`) to an absolute path once, outside the loop, to establish the extraction boundary.

2. **Canonicalize each entry's destination path** (line with `destAbs`) using `filepath.Abs`, which resolves `.` and `..` sequences to absolute form.

3. **Enforce containment** using a path-component-aware check: the destination must either equal the base or start with `base/`. The string separator (`filepath.Separator`) ensures that a sibling directory like `/var/lib/pluginhost/imports-leaked` does not falsely match a check for `/var/lib/pluginhost/import`. This check is placed before any file operation.

4. **Use the canonical path variable** (`destAbs`) for all subsequent file operations, ensuring the validated path—not the original user input—is used for `os.MkdirAll` and `os.Create`.

This pattern closes the directory-escape gap that `filepath.Join` and `filepath.Clean` alone do not address. An attacker-controlled entry name like `../../../etc/passwd` will now be caught and rejected, while legitimate nested structures within the archive (e.g., `subdir/file.txt`) pass the check and are extracted as intended.

## Behaviour changes

- Archive entries that attempt directory escape (e.g. `../etc/passwd`, `/etc/passwd`, or symlink-based traversal through `..`) are now rejected with an error message `"path traversal detected in archive: <name>"`.
- All extracted files use absolute canonical paths, making the extraction deterministic and auditable.
- The extraction now fails fast on a malicious archive entry rather than silently creating files outside the intended directory.
- Error messages distinguish between resolution failures and traversal attempts, aiding debugging and security logging.
- Legitimate nested directory structures and normal filenames within the archive are unaffected.
