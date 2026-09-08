## Verdict

not_exploitable (CWE-78, OS Command Injection) - `Case15B.java:28`

The reported sink is real (`Runtime.getRuntime().exec(osCommand + data)`), but the value concatenated into the command is not attacker-controlled anywhere in the call chain that reaches it. The trace breaks at the point `data` is produced: it is a fixed string literal, never derived from `HttpServletRequest`.

## Source

`Case15A.handle(HttpServletRequest request, HttpServletResponse response)`:

```
String data;
data = "foo";
(new Case15B()).handleSink(data, request, response);
```

`data` is assigned the literal `"foo"` and passed unchanged into `Case15B.handleSink`. `request` and `response` are forwarded alongside it but are never read to populate `data` - no parameter, header, cookie, path, or body value from the request contributes to the string. `handleSink` then builds `osCommand + data` and passes that directly to `Runtime.getRuntime().exec(...)` at line 28, so the sink only ever receives `"c:\WINDOWS\SYSTEM32\cmd.exe /c dir foo"` or `"/bin/ls foo"`.

The two files in this case constitute the entire call chain for the finding; there is no branch, loop, or additional caller within them that assigns `data` from request input.

## Fix

No fix is proposed. Per the workflow, a `not_exploitable` verdict carries no code change - the finding traces to a hardcoded, non-attacker-controlled literal rather than a live injection path, and altering the sink here would not address any actual weakness.

## Explanation

The scanner flagged the `Runtime.exec` call because it concatenates a variable into a command string, which is the correct general shape of a CWE-78 sink. However, tracing that variable back through its only assignment site shows it is set to the constant `"foo"` and is never reassigned from `request` (or any other external input) before reaching the sink. Since the source is not attacker-controlled, there is no data an attacker can influence to inject additional commands or arguments here, so the reported path is not exploitable as written. If `Case15A` is later changed to derive `data` from a request parameter, header, or other external input, this conclusion no longer holds and the sink should be remediated per `cwe/78/INDEX.md` and `cwe/78/java/INDEX.md` (native APIs first, then `ProcessBuilder` with a fixed-argument array and no shell, over the current `cmd.exe /c` / shell-string construction).

## Behaviour changes

none - no code was modified.
