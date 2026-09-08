## Verdict

not_exploitable

## Source

`Case17A.handle(HttpServletRequest request, HttpServletResponse response)` assigns the local variable `data` a fixed string literal:

```
data = "foo";
```

`request` and `response` are present in the method signature but are never read anywhere in `Case17A` - no header, parameter, cookie, or body value is pulled from `request` into `data` or into any other variable that reaches `Case17B`. The literal-valued `data` is then passed unchanged into `Case17B.handleSink(data, request, response)`.

## Fix

No fix is proposed. `verdict` is `not_exploitable`, so no code changes are included.

## Explanation

`Case17B.handleSink` builds an LDAP search filter by concatenating `data` directly into `"(cn=" + data + ")"` (Case17B.java:29) and passes that filter to `directoryContext.search("", search, null)` at the reported sink (Case17B.java:32). That sink is a real, unescaped LDAP-injection sink in general: `DirContext.search(String, String, SearchControls)` performs no filter escaping of its own, and untrusted input concatenated into the filter argument would let an attacker inject filter metacharacters (`)`, `(`, `*`, `\`, null) to alter the query logic or exfiltrate directory attributes.

The break in this specific case is at the source, not the sink. Tracing backward from the sink: `search` is built from `data`; `data` is a parameter of `handleSink`; the only caller in the provided call chain, `Case17A.handle`, supplies `data` from the hardcoded literal `"foo"` rather than from any field of `request`. There is no path in the two files that carries attacker-controlled input into `data` - the `HttpServletRequest` object is passed along by reference but is never dereferenced for a value. Because the value reaching the sink is a compile-time constant, the reported LDAP-injection finding is not exploitable as it stands: the same sink would become exploitable only if a future change wires `data` to something derived from `request` (e.g. a parameter, header, or path segment), at which point the CWE-90 guidance's fix - building the filter with `javax.naming.directory` search rather than string concatenation, or escaping each of `\`, `*`, `(`, `)`, and NUL in the untrusted component before concatenation - would apply.

## Behaviour changes

none - no code was changed.
