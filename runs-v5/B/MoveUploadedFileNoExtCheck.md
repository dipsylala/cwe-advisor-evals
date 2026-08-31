## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - **exploitable**. Confidence: high.

## Source

`$_FILES['avatar']['name']` (client-supplied original filename) and `$_FILES['avatar']['tmp_name']`, read in `handleAvatarUpload()`.

## Fix

Vulnerable code (`MoveUploadedFileNoExtCheck.php`, line 12-17):

```php
$uploadDir = __DIR__ . '/uploads/avatars/';
$originalName = $_FILES['avatar']['name'];
$destination = $uploadDir . $originalName;

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
move_uploaded_file($_FILES['avatar']['tmp_name'], $destination);
```

Fixed code:

```php
<?php
// Handles avatar image uploads for a user profile form.

function handleAvatarUpload(): void
{
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo 'Upload failed.';
        return;
    }

    if (!extension_loaded('fileinfo')) {
        http_response_code(500);
        echo 'Upload failed.';
        return;
    }

    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
    ];

    $tmpName = $_FILES['avatar']['tmp_name'];

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $detectedType = finfo_file($finfo, $tmpName);
    finfo_close($finfo);

    if (!isset($allowedTypes[$detectedType])) {
        http_response_code(400);
        echo 'Unsupported file type.';
        return;
    }

    $extension = $allowedTypes[$detectedType];
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;

    $uploadDir = __DIR__ . '/uploads/avatars/';
    $destination = $uploadDir . $storedName;

    move_uploaded_file($tmpName, $destination);

    echo 'Avatar uploaded successfully.';
}

handleAvatarUpload();
```

## Explanation

The original code built the storage path directly from the client-supplied `$_FILES['avatar']['name']` with no check on the file's real type, so an attacker could upload a `.php` web shell (or any other executable/active-content file) and have it saved, under an attacker-chosen name and extension, into a directory the code treats as a normal upload folder. The fix detects the file's real content type from its bytes with `finfo_file()` (guarding first on `extension_loaded('fileinfo')`, since a missing extension makes the function fatal rather than returning a validation result), rejects anything not on a fixed image-type allowlist, and derives the stored extension from that allowlist rather than from the client-supplied name. The storage filename itself is replaced with a random `bin2hex(random_bytes(16))` value, so the previously tainted `$originalName` never reaches the filesystem path at all - the allowlist-matched extension is the only part of the original name's information that survives, and it comes from the server-side map, not the client string.

## Behaviour changes

- Uploads whose real content does not match the image allowlist (`jpg`/`png`/`gif`/`webp`) are now rejected with HTTP 400 and no file is written; previously every upload that passed the `UPLOAD_ERR_OK` check was stored regardless of type. This rejection is the core of the fix, not incidental.
- If the `fileinfo` extension is unavailable, the request now fails closed with HTTP 500 instead of fataling deeper in the request or (if the check were absent) silently treating an unchecked upload as validated.
- The stored filename is now a random hex name with an allowlist-derived extension instead of the client-supplied original filename; this is the taint-break the guidance requires (`cwe/434/php/INDEX.md`: "Generate the stored filename server-side... never build the storage path from `$_FILES['x']['name']`").
- The return value of `move_uploaded_file()` is still not checked, and the success message is still echoed unconditionally on the path that reaches it - both unchanged from the original, since checking that return value is not part of closing this weakness.
- Storage location (`__DIR__ . '/uploads/avatars/'`) and the absence of an execution-disabling web-server config for that directory are unchanged. The guidance recommends storing outside the document root and disabling script execution in the upload directory as defence-in-depth; both are server/deployment-layer changes outside this file's scope and are not applied here.

### Assumptions

- No explicit MIME allowlist was specified for this endpoint (avatar upload), so the fix assumes common raster image types (`jpeg`, `png`, `gif`, `webp`) as the allowlist. Adjust to the application's actual supported avatar formats if narrower.
