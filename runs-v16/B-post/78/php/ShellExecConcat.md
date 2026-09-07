## Verdict
Exploitable

## Source
- **CWE ID**: CWE-78
- **Location**: evals/cases/78/php/ShellExecConcat/ShellExecConcat.php, line 27
- **Data Flow**: `$_GET['host']` (line 17, untrusted user input) → `$host` parameter → string concatenation into `shell_exec()` command (line 27)

The `$host` value is received from an HTTP GET parameter without validation and concatenated directly into a shell command passed to `shell_exec()`. An attacker can inject shell metacharacters (e.g., `; rm -rf /`, `&& cat /etc/passwd`) to execute arbitrary commands on the host.

## Fix

**Vulnerable code (line 15-34):**
```php
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    $pingCount = 4;

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    $output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');

    if ($output === null) {
        return 'Diagnostic command failed to run.';
    }

    return $output;
}
```

**Fixed code:**
```php
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host is a valid hostname or IP address using strict allowlist
    if (!preg_match('/\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/', $host) &&
        !filter_var($host, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        return 'Invalid host parameter.';
    }

    // Use fsockopen() for network reachability check instead of shell command
    $errno = 0;
    $errstr = '';
    $fp = @fsockopen($host, 80, $errno, $errstr, 2);
    
    if ($fp !== false) {
        fclose($fp);
        $output = "Host $host is reachable on port 80.\n";
    } else {
        $output = "Host $host is not reachable on port 80.\nError: $errstr\n";
    }

    return $output;
}
```

## Explanation

The fix eliminates the OS command injection by replacing `shell_exec()` with PHP's native `fsockopen()` API, which performs a network reachability check without invoking a shell. 

The approach follows CWE-78 PHP remediation guidance: where the command execution is incidental to accomplishing a task (network diagnostics), replace it with a language-native equivalent. Here, `fsockopen()` achieves the same goal—verifying connectivity—by attempting a TCP connection on port 80 (standard HTTP port) without spawning any external process.

Input validation via strict regex (PCRE anchored with `\A` and `\z`) and `filter_var()` ensures the `$host` parameter is either a valid FQDN or IP address before use, preventing both injection and other malformed inputs. The validation uses an allowlist approach rather than escaping, consistent with guidance stating that escaping functions are insufficient as a primary defence.

## Behaviour changes

- **Input validation added**: The fixed code validates `$host` against a hostname/IPv4/IPv6 allowlist before use and returns HTTP 400 if invalid. The original code accepted any string. This is necessary to close the injection; side effect is earlier rejection of malformed input.
- **Command execution method changed**: Replaces `shell_exec()` (shell interpreter invocation) with `fsockopen()` (direct TCP connection). No external process is spawned in the fix.
- **Output format changed**: Original returns raw `ping` command output (e.g., "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data..."). Fixed code returns a simple status string (e.g., "Host 127.0.0.1 is reachable on port 80.\n"). This is a functional trade-off: the original tested ICMP reachability; the fixed code tests TCP reachability on port 80. For internal network diagnostics, TCP port 80 is a reasonable proxy for reachability and is safer.
- **Ping count parameter removed**: The original `$pingCount = 4` variable is unused in the fix because `fsockopen()` performs a single connection test, not repeated pings. This simplifies the logic and has no side effect on functionality.
- **Error handling**: Original returns output string or null (from `shell_exec()` failure). Fixed code always returns a string (either success or error message). The null-check guard at line 29-31 of the original is no longer needed. The fix returns descriptive error messages including the socket error string `$errstr` for diagnostics.

All changes preserve the function's contract (returns string) and maintain the HTTP 400 response pattern for invalid input. The fix does not introduce information leaks—it emits less output than `ping` would, not more.

**Verification**: PHP syntax validated via `php -l` on the fixed function.

**Assumptions**: Assumed port 80 is an acceptable substitute for ping-based reachability testing in an internal admin network diagnostics context. If ICMP ping output is strictly required, an alternative approach using `proc_open()` with argument array (PHP 7.4+, floor 8.1.29/8.2.20/8.3.8 for CVE-2024-5585) would be needed, but `fsockopen()` is preferred per the guidance as it avoids shell execution entirely.
