## Verdict
not_exploitable

## Source
There is no untrusted source in this chain. The only value that reaches the sink originates at `Case17A.java:16` as the string literal `data = "foo"`. The `HttpServletRequest` is in scope at that point but is never read - no `getParameter`, `getHeader`, `getCookies`, `getInputStream`, or any other request accessor is called. The literal is passed to `Case17B.handleSink(data, request, response)` at `Case17A.java:18`, concatenated into the filter at `Case17B.java:29` (`String search = "(cn=" + data + ")";`), and reaches `directoryContext.search("", search, null)` at `Case17B.java:32`. The `request` and `response` parameters are carried along the call but are unused in `Case17B`, so they contribute nothing to the filter. Separately, `Case17A.handle()` is declared `private` and has no caller in this chain, so the servlet container's dispatch cannot reach it either.

## Fix
```java
none - no change required
```

## Explanation
The reported sink is a genuine string-concatenated LDAP filter, which is why the scanner flagged the `directoryContext.search()` call, but the taint analysis is incomplete: the concatenated value is the compile-time constant `"foo"`, which contains no LDAP filter metacharacters and cannot be influenced by a request. The filter that is actually issued is always `(cn=foo)`, so no attacker input can alter the expression tree and there is no injection. The link that breaks the chain is the assignment at `Case17A.java:16` - a literal rather than a request read - and this is reinforced by `Case17A.handle()` being private and unreachable from the container's dispatch. This finding can be suppressed with a justification recording that the filter component is a hardcoded constant. That suppression should be reviewed if `data` is ever changed to derive from the request, the method is made public or wired to a dispatch path, or the sink is refactored into a shared helper reachable from tainted callers; in any of those cases the correct remediation is JNDI's parameterized `DirContext.search(String, String, Object[], SearchControls)` overload rather than filter concatenation.
