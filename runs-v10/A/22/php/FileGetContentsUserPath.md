## Verdict
Path traversal vulnerability confirmed. User-controlled input from `$_GET['file']` is used to construct a file path without validation, allowing directory escape sequences.

## Source
Line 9 assigns unsanitized user input directly to `$name`:
```
$name = $_GET['file'];
```

Line 14 concatenates this into the file path:
```
$path = $reportsDir . '/' . $name;
```

Line 17 passes the unsanitized path to `file_get_contents()`, making it the sink.

An attacker can supply `?file=../../../../etc/passwd` to read files outside `/var/www/reports`.

## Fix
Apply `basename()` to the user input before constructing the path. This removes all directory components, allowing only the filename itself:

```php
$name = basename($_GET['file']);
$path = $reportsDir . '/' . $name;
$contents = file_get_contents($path);
```

## Explanation
`basename()` extracts only the trailing filename component of a path, stripping all directory separators and traversal sequences. Calling `basename('../../../../etc/passwd')` returns `'passwd'`, converting the malicious traversal attempt into a safe filename lookup under the intended directory. The rest of the control flow remains unchanged: if the file does not exist, `file_get_contents()` returns `false`, triggering the 404 response as intended.
