## Verdict

OS Command Injection via unsanitized user input concatenated into a shell command string. The `$_GET['host']` parameter is concatenated directly into the `system()` call without validation or parameterization, allowing arbitrary shell commands to be injected.

## Source

File: `SystemFunctionConcat.php`, Line 8

```php
system('ping -c 2 -W 2 ' . $host, $resultCode);
```

The `$host` parameter originates from untrusted user input (`$_GET['host']`) at line 17 and flows directly into the shell command string at line 8 via string concatenation.

## Fix

### File: SystemFunctionConcat.php

```php
<?php

function check_host_reachability(string $host): array
{
    // Validate host is not empty to prevent error conditions
    if (empty($host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    $descriptorspec = array(
        1 => array('pipe', 'w'),  // stdout
        2 => array('pipe', 'w'),  // stderr
    );

    // Use proc_open with array form to avoid shell injection
    // '--' before $host prevents it from being interpreted as an option by ping
    $process = proc_open(
        ['ping', '-c', '2', '-W', '2', '--', $host],
        $descriptorspec,
        $pipes
    );
    
    if ($process === false) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Close the pipes to prevent pipe buffer from blocking
    if (isset($pipes[1])) {
        fclose($pipes[1]);
    }
    if (isset($pipes[2])) {
        fclose($pipes[2]);
    }

    $resultCode = proc_close($process);

    return [
        'host' => $host,
        'reachable' => $resultCode === 0,
    ];
}

header('Content-Type: application/json');
$status = check_host_reachability($_GET['host'] ?? '');
echo json_encode($status);
```

## Explanation

The fix replaces `system()` with `proc_open()` using array form for command arguments. In `proc_open()`, passing an array as the first parameter (available in PHP 7.4+) causes each array element to be passed as a separate argument to the process, completely bypassing the shell. This prevents shell metacharacter interpretation and stops command injection attacks.

The `--` literal argument is placed before the `$host` parameter. This is an end-of-options marker that tells ping to treat everything after it as a destination, preventing a host value starting with `-` from being misinterpreted as a flag (CWE-88 mitigation).

Input validation checks that `$host` is not empty; empty input returns `reachable: false` rather than attempting to run ping with no destination.

The `proc_close()` function is called after closing the pipes to retrieve the exit code, which replaces the exit code reference parameter that `system()` provided. The return value structure and logic remain unchanged, preserving the original API contract.

For PHP versions 8.1.29+, 8.2.20+, or 8.3.8+, this approach is fully protected against shell escaping due to CVE-2024-1874 and CVE-2024-5585 fixes. For older PHP versions on Windows, the `bypass_shell` option in proc_open's options parameter provides additional protection.

## Behaviour changes

- Process execution method: `system()` → `proc_open()` with argument array
- Command construction: string concatenation → array of separate arguments
- Empty host input: previously would run `ping -c 2 -W 2` with no destination; now returns `reachable: false` without running ping
- Stdout/stderr handling: `system()` sent output to stdout/stderr directly; `proc_open()` pipes are opened but not read from, then closed (output is discarded)
- Exit code retrieval: `system()` reference parameter → `proc_close()` return value
- Return value structure: unchanged (array with 'host' and 'reachable' keys)
- Reachability logic: unchanged (exit code 0 means reachable)
- Function signature: unchanged
