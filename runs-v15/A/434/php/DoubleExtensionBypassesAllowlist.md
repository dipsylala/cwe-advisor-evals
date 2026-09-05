## Verdict

**CONFIRMED.** The code is vulnerable to file upload bypass via double extension attacks. The validation checks whether an allowed extension appears anywhere in the filename using `strpos()`, which permits files like `shell.php.jpg` to bypass the check. These files can be executed as PHP on misconfigured servers.

## Source

The vulnerability is in the extension validation logic at lines 20–25. The code checks:

```php
if (strpos(strtolower($originalName), $ext) !== false) {
```

This finds the extension anywhere in the string. A file named `shell.php.jpg` contains `.jpg`, passes the check, and is then stored with its original name via `move_uploaded_file($file['tmp_name'], $destination)` at line 36. If the web server is configured to execute `.php` files regardless of later extensions, or if it processes the first executable extension in a chain, the PHP payload executes.

The root cause is conflating "filename contains an allowed extension" with "filename ends with an allowed extension."

## Fix

Extract the actual file extension (the final dot-separated segment after the last dot) and check only that value against the allowlist. Generate a sanitized filename from a safe basename rather than trusting the original:

```php
function handleAvatarUpload(array $file, string $uploadDir): array
{
    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'Upload failed'];
    }

    $originalName = $file['name'];
    $allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    
    // Extract the actual file extension (after the last dot).
    $fileExtension = strtolower(strrchr($originalName, '.'));
    if ($fileExtension === false) {
        $fileExtension = '';
    }
    
    // Check if the actual extension is in the allowlist.
    if (!in_array($fileExtension, $allowedExtensions, true)) {
        return ['ok' => false, 'error' => 'Unsupported file type'];
    }
    
    // Generate a safe, collision-resistant filename with only the allowed extension.
    // Use a timestamp or UUID plus the verified extension to prevent overwrites and
    // ensure the stored filename contains only the intended extension.
    $safeFilename = bin2hex(random_bytes(16)) . $fileExtension;
    $destination = $uploadDir . '/' . $safeFilename;
    
    move_uploaded_file($file['tmp_name'], $destination);
    
    return ['ok' => true, 'path' => $destination];
}
```

## Explanation

**Why the original code failed:**

- `strpos($originalName, '.jpg')` finds the substring anywhere, so `evil.php.jpg` contains `.jpg` and passes.
- The allowlist check and the actual file extension are two different things. The check should inspect only the true extension, which is the text after the last dot.

**Why the fix works:**

1. `strrchr($originalName, '.')` extracts only the final dot and everything after it—the actual file extension as the OS and web server interpret it.
2. `in_array($fileExtension, $allowedExtensions, true)` checks exact match against the allowlist, rejecting any file that does not end with an approved extension.
3. Generating a sanitized filename (`bin2hex(random_bytes(16)) . $fileExtension`) ensures:
   - No attacker control over the stored name
   - No double-extension bypasses (the stored file ends only with the approved extension)
   - No collisions (random bytes are collision-resistant)
   - Predictable, audit-friendly filenames that carry only the extension the check verified

**Defence in depth:**

- Even if the web server is misconfigured to execute `.php.jpg`, the stored filename will be something like `a1b2c3d4e5f6...jpg`, containing no `.php`.
- This approach also mitigates directory traversal via filenames (e.g., `../../../etc/passwd.jpg`) because the generated name is a flat, random string.
