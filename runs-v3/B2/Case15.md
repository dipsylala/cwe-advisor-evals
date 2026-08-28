## Verdict

not_exploitable

## Source

Sink: `Case15B.java:28`, `Runtime.getRuntime().exec(osCommand + data)` inside `Case15B.handleSink(String data, HttpServletRequest request, HttpServletResponse response)`. The command string is built by concatenation, so anything reaching `data` would be re-parsed as command text.

Tracing backwards from the sink:

- `osCommand` (`Case15B.java:14-24`) is one of two hardcoded string literals - `"c:\WINDOWS\SYSTEM32\cmd.exe /c dir "` or `"/bin/ls "` - selected by `System.getProperty("os.name")`. The branch selector is a JVM-controlled system property, not request data, and neither branch value is attacker-influenced.
- `data` is a method parameter. Its only call site in the chain is `Case15A.java:18`, `(new Case15B()).handleSink(data, request, response)`.
- In `Case15A.handle` (`Case15A.java:11-19`), `data` is declared at line 13 and assigned the constant literal `"foo"` at line 16. There is no intervening read of `request` - no `getParameter`, `getHeader`, `getCookies`, `getQueryString`, `getInputStream`, or any other request accessor - and no other assignment to `data` before the call.
- `request` and `response` are forwarded into `handleSink` but never dereferenced there; `handleSink` reads only `data` and `System.getProperty("os.name")`.

So the path the finding describes ends at a compile-time constant. The breaking link is the assignment at `Case15A.java:16`: the parameter that reaches the concatenation is bound to the literal `"foo"`, and no untrusted value enters the chain at any point between the servlet entry point and the sink. The executed command is fixed at `/bin/ls foo` or `cmd.exe /c dir foo`.

For completeness, the sink's existing contract: it returns a `Process` used only for `waitFor()`; stdout and stderr are deliberately discarded (never read), the exit status is ignored, and the method propagates `IOException`/`InterruptedException` to the caller via `throws Throwable`.

## Fix

No change is proposed. The reported path carries no attacker-controlled data, so modifying it would alter working code without removing a reachable weakness.

The finding can be suppressed with the justification that `data` is the constant literal `"foo"` assigned at `Case15A.java:16` and is never derived from the `HttpServletRequest`.

One thing worth recording rather than changing: `handleSink` is `public`, so the safety of line 28 rests entirely on its callers, not on anything the method itself enforces. If a future caller passes a request-derived value, the concatenation at line 28 becomes injectable immediately - `Runtime.exec(String)` tokenizes on whitespace, and the Windows branch additionally routes through `cmd.exe /c`, where shell metacharacters are re-interpreted. Should the method ever need to accept caller-supplied input, the command should be rebuilt as a separate argument list (`ProcessBuilder` with the executable and its arguments as distinct elements, invoking the target program directly rather than through `cmd.exe`), with the argument validated against an allowlist before use.

## Explanation

Nothing changed. The scanner flagged string concatenation into `Runtime.exec()`, which is the correct shape for CWE-78, but the taint analysis stopped at the method boundary of `handleSink` and treated its `String data` parameter as untrusted because the method also receives an `HttpServletRequest`. Following the single call edge into `Case15A.handle` shows the parameter is supplied as the literal `"foo"`, and the request object is passed through without ever being read on either side of the boundary. With both the command prefix and the appended value fixed at compile time, no attacker can influence the string handed to `exec`, so there is no injection to close and no code change that would improve the security of this path. The residual concern is structural rather than active - the method's safety is a property of its current caller, not of the method - so it is recorded above as a caller-contract note instead of being treated as a defect to patch.

## Behaviour changes

none - no code change is proposed, so the sink contract at `Case15B.java:28-29` is untouched: the process is still spawned and awaited, its stdout and stderr remain unread, its exit status remains ignored, and `IOException`/`InterruptedException` still propagate to the caller.
