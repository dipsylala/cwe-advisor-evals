## Verdict
exploitable

## Source
`IFormFile file` parameter (line 25) — attacker-supplied uploaded file

## Fix

**Vulnerable code (line 32-39):**
```csharp
using var stream = file.OpenReadStream();

var header = new byte[8];
// SAST FINDING: CWE-434 reported here
int bytesRead = stream.Read(header, 0, header.Length);

bool isPng = header.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
bool isPdf = header.AsSpan(0, PdfSignature.Length).SequenceEqual(PdfSignature);
```

**Fixed code:**
```csharp
using var stream = file.OpenReadStream();

var header = new byte[8];
int bytesRead = 0;
int read;
while (bytesRead < header.Length && (read = stream.Read(header, bytesRead, header.Length - bytesRead)) > 0)
{
    bytesRead += read;
}

if (bytesRead < header.Length)
{
    return BadRequest("File too small.");
}

bool isPng = header.AsSpan(0, PngSignature.Length).SequenceEqual(PngSignature);
bool isPdf = header.AsSpan(0, PdfSignature.Length).SequenceEqual(PdfSignature);
```

## Explanation

The vulnerability is a short-read bypass of file-type validation: `Stream.Read()` can return fewer bytes than requested without indicating an error. The original code calls `Read(header, 0, 8)` but does not check whether all 8 bytes were actually read. If `Read()` returns 4 bytes (e.g., because the file is small or contains only a partial magic sequence), the remaining 4 bytes in the buffer remain uninitialized. The subsequent signature comparison then operates on incomplete data—potentially all zeros—allowing a file with only 4 bytes of valid PNG or PDF magic bytes to pass the type check.

The fix loops `Read()` until exactly the required header length is filled or EOF is reached. It then validates that all 8 bytes were read before performing the signature comparison. If the file is too small, it returns a 400 error instead of proceeding with an incomplete header check. This ensures the signature comparison always operates on the actual file content, closing the bypass.

## Behaviour changes

- **Loop instead of single read**: The fix calls `Read()` potentially multiple times until the full header is available. This handles the case where a single `Read()` returns fewer bytes than requested, which is standard stream behavior.
- **Early rejection on short file**: If EOF is reached before 8 bytes are available, the request now returns `BadRequest("File too small.")` instead of allowing the comparison to proceed against zeroed/uninitialized bytes. This prevents a file-type mismatch from being silently accepted.
- **Variable semantics unchanged**: `bytesRead` retains the total number of bytes read from the stream header and is still returned in the 200 response, preserving the original response contract.

