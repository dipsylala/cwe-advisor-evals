## Verdict

Not exploitable as reported. `Case15B.handleSink()` does build a shell command by concatenating
`osCommand + data` and pass it to `Runtime.getRuntime().exec(...)`, which is a genuine CWE-78 sink
shape. But in this call chain the `data` argument is not attacker-controlled: `Case15A.handle()`
assigns `data = "foo";` - a fixed string literal - before calling `handleSink()`. The
`HttpServletRequest`/`HttpServletResponse` parameters that flow into both methods are never read
(no `getParameter`, `getHeader`, `getInputStream`, cookies, etc.), so no external input reaches the
sink through this path. There is no injectable data flow to remediate here.

## Source

None. The only candidate source objects are `request` and `response`, and neither is queried for
any value anywhere in `Case15A` or `Case15B`. The value that actually reaches the sink,
`data`, originates from the literal assignment `data = "foo";` on line 16 of `Case15A.java`.

## Fix

No code change is required for this call chain, since it processes no external input. The sink
pattern itself is fragile, though, and should be hardened defensively so that a future caller
cannot introduce a real vulnerability by passing request-derived data into `handleSink()`:

```java
public class Case15B
{
    public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        // Reject anything that is not a simple filename/path segment before it can
        // reach a directory-listing command.
        if (data == null || !data.matches("[A-Za-z0-9._-]{1,255}"))
        {
            throw new IllegalArgumentException("Invalid argument for directory listing");
        }

        List<String> command = new ArrayList<>();
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            command.add("cmd.exe");
            command.add("/c");
            command.add("dir");
        }
        else
        {
            command.add("/bin/ls");
        }
        command.add(data);

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        process.waitFor();
    }
}
```

This replaces the shell-string concatenation with `ProcessBuilder` and an explicit argument list
(no shell is invoked, so shell metacharacters in `data` cannot be interpreted), and adds an
allowlist check on `data` so that even a future caller who wires in request-derived input cannot
pass shell metacharacters, path separators, or option-like strings (e.g. a leading `-`) through to
the external process.

## Explanation

`Runtime.getRuntime().exec(String)` (and the `osCommand + data` string concatenation feeding it)
is the classic CWE-78 sink: on Windows it runs the string through `cmd.exe /c`, which interprets
shell metacharacters such as `&`, `|`, `;`, and `` ` `` in whatever is appended to `osCommand`. If
`data` were ever populated from `request` (a query parameter, header, or body field), an attacker
could append `& del /Q *` or similar to run an arbitrary second command. The reason this specific
finding is not currently exploitable is that the only value that reaches `handleSink()` in this
program is the hardcoded literal `"foo"` set in `Case15A.handle()` - `request` and `response` are
threaded through both methods but never inspected for data, so there is no path from an external
input to the sink today. The suggested fix (argument-array `ProcessBuilder` plus an allowlist
check on `data`) is included as defense-in-depth so that if `handleSink()` is later called with
request-derived data - which its signature already invites, since it accepts an
`HttpServletRequest` - the method remains safe rather than becoming a live injection point.
