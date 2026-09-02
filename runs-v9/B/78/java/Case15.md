## Verdict

not_exploitable (confidence: high)

## Source

`Case15A.handle(HttpServletRequest request, HttpServletResponse response)` (Case15A.java, line 16):

```
data = "foo";
```

`data` is assigned a fixed string literal - it is never read from `request` (no `getParameter`, header, cookie, path, or body access anywhere in the call chain) or from any other attacker-influenced input. It is then passed unchanged into `Case15B.handleSink(data, request, response)` (Case15A.java, line 18).

## Fix

No fix proposed. The value that reaches the sink is a compile-time constant, so there is no attacker-controlled data to remediate.

## Explanation

The reported sink is `Runtime.getRuntime().exec(osCommand + data)` in `Case15B.handleSink` (Case15B.java, line 28), where `osCommand` is one of two hardcoded strings (`cmd.exe /c dir` or `/bin/ls`, chosen only by `os.name`) and `data` is the literal `"foo"` set in `Case15A.handle`. `handleSink` also receives `request` and `response`, but neither is read anywhere in the method - no parameter, header, path, or body value is extracted from them before the `exec` call. Tracing the full path from the servlet entry point to the sink therefore shows every value concatenated into the command string is a fixed literal chosen by the code itself, not by a caller. Because there is no source of attacker-controlled input anywhere on this path, the reported OS command injection is not exploitable as flagged: the breaking link is at the source, `data`, which never carries external input despite the method signature exposing `HttpServletRequest`/`HttpServletResponse`. No code change is proposed, since introducing validation or a parameterized-exec rewrite here would not correspond to any real data-flow weakness.

## Behaviour changes

none - no fix was applied.
