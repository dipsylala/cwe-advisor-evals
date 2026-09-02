## Verdict

Not exploitable. CWE-90 (LDAP Injection) does not hold at this sink as reported.

## Source

`Case17A.handle(HttpServletRequest request, HttpServletResponse response)` declares `data` and assigns it the literal `data = "foo";`. `request` is never read - no parameter, header, cookie, or body value is pulled from it anywhere in the method. `data` is then passed unchanged into `Case17B.handleSink(data, request, response)`, where it is concatenated into the filter string `"(cn=" + data + ")"` and passed to `directoryContext.search("", search, null)` at line 32.

The value that reaches the LDAP filter is a fixed string constant, not attacker-controlled input. The call chain from the `HttpServletRequest` source to the `DirContext.search()` sink is broken at the very first step in `Case17A`: no data ever leaves the request object and enters `data`.

## Fix

No code change proposed. Since the reported source-to-sink path carries no untrusted data, applying an LDAP-escaping or parameterized-filter fix here would not close any real weakness - `data` is always the literal `"foo"`, which contains no LDAP metacharacters and cannot be influenced by a caller.

If `Case17A` is a simplified stand-in for code that is meant to read a request parameter (e.g. `request.getParameter(...)`) into `data`, that read is missing from the current file. Should that assignment be added later, the sink at `Case17B.java:32` would then require remediation per `cwe/90/java/INDEX.md`: replace `"(cn=" + data + ")"` with JNDI's parameterized filter overload - `directoryContext.search("", "(cn={0})", new Object[]{ data }, new SearchControls())` - so the JDK escapes the value per RFC 4515 instead of concatenating it into the filter string.

## Explanation

The static analysis tool flagged `directoryContext.search()` because it structurally matches the LDAP-injection sink pattern (a concatenated string built from a method parameter, passed to `DirContext.search()`). Tracing the actual data flow from the `HttpServletRequest` source through `Case17A` to the sink in `Case17B` shows the parameter is never populated from the request - it is hardcoded to `"foo"` - so there is no reachable path by which an attacker can influence the LDAP filter. This is a false positive as currently written, not a case requiring a code fix.

## Behaviour changes

None - no fix was applied, since the verdict is not_exploitable and the source code was not modified.
