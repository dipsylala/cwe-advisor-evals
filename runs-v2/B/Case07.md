## Verdict
exploitable

## Source
Untrusted data enters at `Case07A.java:16` - `data = request.getParameter("name")`, an attacker-controlled HTTP request parameter. `Case07A.handle()` is a public servlet entry point (`Case07A extends AbstractTestCaseServlet`), so the value is reachable from a remote request. It is passed unchanged to `Case07B.handleSink(data, request, response)` at `Case07A.java:18`. Inside `Case07B.handleSink`, the parameter is concatenated into an LDAP search filter at `Case07B.java:29` (`String search = "(cn=" + data + ")";`) and that filter string reaches the sink `directoryContext.search("", search, null)` at `Case07B.java:32`. No validation, encoding, or length/character restriction is applied anywhere along the path.

## Fix
```java
            String search = "(cn={0})";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, null);
```

## Explanation
The filter was built by string concatenation, so any LDAP filter metacharacter in the `name` parameter is parsed as filter syntax rather than as data: a payload such as `*)(objectClass=*` closes the `cn` term and appends an attacker-chosen clause, turning a targeted lookup into a match-everything query and exposing directory entries the caller was never meant to read. The fix switches to JNDI's parameterized `DirContext.search(String, String, Object[], SearchControls)` overload, where `{0}` is a placeholder and the untrusted value is supplied through `filterArgs`; the JDK escapes each argument per RFC 4515 before substituting it, so `*`, `(`, `)`, and backslash are treated as literal characters of the search term and the filter structure stays fixed regardless of input. The query semantics are unchanged for legitimate values, and no new dependency is required. As defence in depth, the search should also use a narrow base DN, restricted returned attributes, and a least-privileged bind account.
