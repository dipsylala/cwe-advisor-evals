## Verdict

exploitable

- cwe_id: CWE-78
- location: ProcOpenShellString.php, line 18 (sink: `proc_open()` call inside `searchApplicationLog()`)
- confidence: high

## Source

`$_GET['term']` (line 41) flows unmodified into the `$term` parameter of `searchApplicationLog()` (line 42), which concatenates it directly into a shell command string with no escaping or quoting.

## Fix

### File: ProcOpenShellString.php

```php
<?php

/**
 * Streams matching lines from the daily application log back to an
 * operator so they can search for a request ID or error string without
 * shelling into the box.
 */
function searchApplicationLog(string $term): array
{
    $logPath = '/var/log/app/access.log';

    $handle = @fopen($logPath, 'r');
    if ($handle === false) {
        return ['matches' => [], 'error' => 'unable to start search'];
    }

    $matches = [];
    while (($line = fgets($handle)) !== false) {
        $line = rtrim($line, "\r\n");
        if (str_contains($line, $term)) {
            $matches[] = $line;
        }
    }
    fclose($handle);

    return ['matches' => $matches, 'error' => null];
}

// Example endpoint wiring: GET /admin/log-search?term=...
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);

header('Content-Type: application/json');
echo json_encode($result);
```

## Explanation

The original code built a shell command string by concatenating unsanitized user input (`$term`) into `grep -F -- "..."` and handed it to `proc_open()` as a single string, which PHP executes through a shell (`sh -c` / `cmd.exe`) — a `"` or `` ` `` in `term` breaks out of the quoted argument and lets an attacker run arbitrary commands. Here the command is incidental: it exists only to do a fixed-string substring search over a local file, an operation PHP's file I/O already performs natively. The fix eliminates the shell invocation entirely — no `proc_open()`, no external process — by opening `$logPath` directly with `fopen()`, reading it line by line with `fgets()`, and testing each line with `str_contains($line, $term)`, which mirrors `grep -F`'s literal (non-regex), case-sensitive substring semantics. Because `$term` is now only ever compared as a plain string value and never assembled into a command, there is no injection point left to protect: the class of vulnerability is removed rather than mitigated.

## Behaviour changes

- Matching semantics: `str_contains()` performs the same literal, case-sensitive substring match as `grep -F` on each line, so the `matches` array contains the same lines for the same input in the normal case. Reason: required to keep result parity while removing the shell sink.
- Startup-failure message: the original returned `'unable to start search'` only when `proc_open()` failed to return a resource (rare); it returned `trim($errors)` (the process's stderr, e.g. a "no such file" message from `grep`) when the process started but exited with code > 1. The fix has no external process or stderr stream, so every failure to read the log (missing file, permission denied) now returns the same `'unable to start search'` message instead of a grep-derived stderr string. Reason: unavoidable once the shell/process is removed; the `error` key's presence and the `matches: []` shape are preserved, only the specific text differs on this failure path.
- Trailing-newline handling: lines are trimmed of `\r\n`/`\n` before comparison and before being added to `matches`, matching the original's `explode("\n", trim($output))` behavior of returning lines without trailing newlines. No functional difference for the normal (matches-found) case.
- Requires PHP 8.0+ for `str_contains()`. The rest of the file's syntax was already compatible; no other language-version constraint changes.

## Verification

Ran `php -l` against the fixed file in a scratch location: "No syntax errors detected". Additionally ran the extracted matching logic against a small in-memory test log (3 lines, one containing a target substring) via `php` CLI: confirmed it returns the matching line for a normal search term, returns `matches: []` / `error: null` for a term with no matches, returns `matches: []` / `error: null` (no execution) for a payload containing `"; touch /tmp/pwned #` (proving the former injection string is now inert, treated as a literal substring), and returns `matches: []` / `error: 'unable to start search'` when the target file does not exist.
