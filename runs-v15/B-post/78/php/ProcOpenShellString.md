## Verdict
exploitable

## Source
`$_GET['term']` passed to `searchApplicationLog()` at line 41 of the case file, untrusted user input from an HTTP query parameter.

## Fix

**Vulnerable code (line 18):**
```php
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);
```

**Fixed code:**
```php
// Validate input - reject values starting with dash to prevent option injection
if (substr($term, 0, 1) === '-') {
    return ['matches' => [], 'error' => 'search term cannot start with a dash'];
}

$logPath = '/var/log/app/access.log';
$descriptors = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

// Use argument array form to avoid shell injection (PHP 7.4+)
$process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);
```

## Explanation
The original code concatenates user input directly into a shell command string, allowing attackers to inject shell metacharacters or additional commands. The fix replaces the vulnerable string form with `proc_open()`'s argument array form (available in PHP 7.4+), which passes each argument directly to the program without shell processing. The input validation layer rejects values starting with `-` to prevent option injection attacks, where an attacker could supply a flag like `--help` to alter grep's behavior. This dual approach (argument array + input validation) closes both shell-metacharacter and argument-injection vectors for this sink.

## Behaviour changes
The fix adds input validation that rejects search terms starting with a dash character. This is a functional change: legitimate searches beginning with `-` will now return an error instead of executing. The justification is that grep interprets leading dashes as option flags, so this constraint is necessary to prevent option-injection attacks. The rest of the code flow remains unchanged—the function still returns a hash with `matches` and `error` keys, and stream handling is identical.
