## Verdict

**CONFIRMED EXPLOITABLE**

The vulnerable code constructs and executes a shell command string using untrusted user-supplied paths, allowing arbitrary command injection through shell metacharacters.

## Source

User-supplied `inputPath` and `outputPath` parameters (from the function signature) are concatenated into a shell command string without sanitization or validation.

The data flow:
1. `inputPath` and `outputPath` parameters enter the function
2. Line 9: Values are incorporated into `shellCmd` via `fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)`
3. Line 12: The concatenated string is passed to `exec.Command("sh", "-c", shellCmd)` - the sink
4. Line 13: The command is executed via `cmd.Run()`

An attacker-controlled path containing shell metacharacters (`;`, `|`, `&&`, `$()`, backticks, etc.) will be interpreted by the shell rather than passed as literal argument data.

## Fix

Replace shell invocation with Go native image processing libraries. This eliminates the command execution sink entirely, which is the primary defence according to CWE-78 guidance.

**Original (vulnerable):**
```go
func ResizeImage(inputPath, outputPath string) error {
	shellCmd := fmt.Sprintf("convert %s -resize 800x600 %s", inputPath, outputPath)

	// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
	cmd := exec.Command("sh", "-c", shellCmd)
	return cmd.Run()
}
```

**Fixed:**
```go
package imaging

import (
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"

	"golang.org/x/image/draw"
)

func ResizeImage(inputPath, outputPath string) error {
	// Open and decode input image
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input image: %w", err)
	}
	defer inFile.Close()

	img, _, err := image.Decode(inFile)
	if err != nil {
		return fmt.Errorf("failed to decode image: %w", err)
	}

	// Calculate dimensions, preserving aspect ratio to fit within 800x600
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	var resized image.Image
	if width > 800 || height > 600 {
		// Calculate scale factor
		scale := 1.0
		scaleX := float64(800) / float64(width)
		scaleY := float64(600) / float64(height)
		if scaleX < scaleY {
			scale = scaleX
		} else {
			scale = scaleY
		}

		newWidth := int(float64(width) * scale)
		newHeight := int(float64(height) * scale)

		// Resize using high-quality bilinear resampling
		dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
		draw.BiLinear.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)
		resized = dst
	} else {
		resized = img
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Encode to output format based on file extension
	ext := strings.ToLower(filepath.Ext(outputPath))
	switch ext {
	case ".jpg", ".jpeg":
		return jpeg.Encode(outFile, resized, &jpeg.Options{Quality: 90})
	case ".png":
		return png.Encode(outFile, resized)
	default:
		// Default to PNG
		return png.Encode(outFile, resized)
	}
}
```

**Add import:** `"strings"` to the existing imports.

**Dependencies:**
- `image`, `image/jpeg`, `image/png`, `image/draw` - Go standard library
- `golang.org/x/image/draw` - standard image processing library, no security-specific version constraint

## Explanation

The fix eliminates the injection sink entirely by replacing the external `convert` command with Go's native image processing libraries. This follows CWE-78's primary remediation strategy: "where the command is incidental to what the code needs to do, eliminate system command execution entirely by using language-native library alternatives."

The original code's contract is preserved:
- Returns `error` for any operation failure
- Processes images from input path to output path
- Resizes to fit within 800×600 maintaining aspect ratio
- Encodes to JPEG (quality 90) or PNG based on file extension

The redesigned code:
- Uses `os.Open()` and `image.Decode()` to read the input (no shell, format auto-detected)
- Uses `golang.org/x/image/draw.BiLinear.Scale()` for high-quality resampling (replaces ImageMagick's resize)
- Uses `image/jpeg.Encode()` and `image/png.Encode()` to write output
- Accepts input/output paths as normal file-system strings with no shell interpretation
- Reports errors clearly without hiding failures in shell exit codes

Since file paths are now passed directly to `os.Open()` and `os.Create()` rather than a shell interpreter, shell metacharacters and command substitution patterns are treated as literal path characters. Path traversal is still possible (inputPath could contain `../`), but that is a separate concern (CWE-22); command injection is eliminated.

## Behaviour changes

**Security:**
- Injection via shell metacharacters is eliminated - the path strings are never parsed by a shell
- No execution of arbitrary commands possible through inputPath or outputPath

**Functional:**
- Resize algorithm changes from ImageMagick to Go's bilinear resampling - output pixel values may differ slightly
- If input is already smaller than 800×600, it is returned unchanged (no upscaling)
- Output format detection now based on file extension; ImageMagick inference is not replicated
- Image metadata/EXIF is not preserved (the original also discarded it)
- Timeout behaviour changes: ImageMagick invocation had no timeout; native resize is bounded by Go's runtime, typically much faster

**Error handling:**
- Original: shell exit codes wrapped as errors (opaque to caller)
- Fixed: structured errors from file I/O and image decoding (more debuggable)
- If outputPath is a directory or unwritable, `os.Create()` fails immediately rather than after ImageMagick completes
