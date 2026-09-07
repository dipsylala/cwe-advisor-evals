## Verdict

Exploitable

## Source

`$_GET['host']` (line 17) flows unsanitized into the `system()` sink

## Fix

**Vulnerable code (line 8):**

```php
system('ping -c 2 -W 2 ' . $host, $resultCode);
```

**Fixed code:**

```php
// Validate host is not empty and is a valid IPv4 address or hostname
if (empty($host) || !preg_match('/\A(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)\z/i', $host)) {
    return [
        'host' => $host,
        'reachable' => false,
    ];
}

// Use fsockopen instead of system() to check host reachability
$fp = @fsockopen($host, 80, $errno, $errstr, 2);
if ($fp) {
    $resultCode = 0;
    fclose($fp);
} else {
    $resultCode = 1;
}
```

## Explanation

The vulnerability allowed arbitrary shell command execution through unsanitized user input passed to `system()`. The remediation replaces the shell-based `ping` command with `fsockopen()`, a native PHP function for network connectivity checks. Input validation using a regex anchored with `\A` and `\z` ensures only valid hostnames and IPv4 addresses are accepted, rejecting anything that could contain shell metacharacters or be misinterpreted. The fix closes the injection point entirely by removing shell execution while preserving the original function's return structure and reachability semantics (TCP connectivity to port 80).

## Behaviour changes

1. **Reachability check mechanism changed**: Original uses ICMP ping; fixed version checks TCP connectivity to port 80. This is a necessary trade-off to eliminate command injection.
2. **Invalid input handling**: Original would attempt to execute invalid input as a shell command; fixed version validates the host and returns `reachable: false` for invalid formats. This prevents shell injection and improves robustness.
3. **Connection timeout**: Fixed version uses 2-second timeout for fsockopen (consistent with original `-W 2` flag).
4. **Error suppression**: Added `@` operator to `fsockopen()` to suppress PHP warnings on connection failure (connection failure itself is caught via the conditional).
5. **Return value preserved**: Both versions return the same array structure with `host` and `reachable` fields; the calling code's JSON output remains identical in structure.

