## Verdict

not_exploitable

## Source

There is no untrusted source on this chain.

- `e:/Github/cwe-advisor/evals/cases-v2/Case15/Case15A.java` line 16 - `data = "foo"`, a hardcoded string literal. The `HttpServletRequest` is in scope at this point but is never read; no `request.getParameter`, `getHeader`, `getCookies`, `getInputStream`, or any other request accessor is called anywhere in the chain.
- `Case15A.java:18` - the literal is passed to `(new Case15B()).handleSink(data, request, response)`.
- `Case15B.java:11` - received as `data`; the `request` argument is carried along but never read.
- `Case15B.java:28` (sink) - `Runtime.getRuntime().exec(osCommand + data)` executes `cmd.exe /c dir foo` or `/bin/ls foo`.

The command string is therefore fully constant at every invocation. The breaking link is the assignment at `Case15A.java:16`: the value reaching the sink originates from program text, not from any attacker-influenced input.

A secondary observation, not relied on for the verdict: `handle` in `Case15A` is declared `private`, so it is not the servlet's dispatched entry point and appears to have no in-repo caller. Even if it were reachable, the constant assignment alone settles the outcome.

## Fix

```java
none - no change required
```

## Explanation

The sink at `Case15B.java:28` is a genuine command-execution call and would be dangerous with attacker-controlled input, but on this chain the value it concatenates is the literal `"foo"` assigned at `Case15A.java:16` and passed through unchanged, so the executed command line is identical on every run and contains nothing an attacker can influence. The scanner flagged the sink pattern - string concatenation into `Runtime.exec` - without establishing a source, and no source exists here: the `HttpServletRequest` parameter threaded through both methods is never read. No code change is warranted; the finding should be suppressed with a justification recording that the sink argument is a compile-time constant. That suppression is specific to this data flow and should be revisited if `Case15A` is ever changed to populate `data` from the request or from any other external input, at which point the sink becomes exploitable exactly as written.
