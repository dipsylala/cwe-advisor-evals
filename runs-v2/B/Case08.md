## Verdict
exploitable

## Source
Untrusted data enters at `Case08A.java:16` - `data = request.getParameter("name")`, an attacker-controlled HTTP request parameter read in the public servlet entry point `Case08A.handle()` (`Case08A extends AbstractTestCaseServlet`). The value is forwarded unmodified through three hops: `Case08A.java:18` calls `Case08B.handleSink`, `Case08B.java:12` calls `Case08C.handleSink`, and `Case08C.java:12` calls `Case08D.handleSink`. Each intermediate method is a pure pass-through with no validation or encoding. In `Case08D.handleSink` the value is concatenated into an LDAP search filter at `Case08D.java:29` (`String search = "(cn=" + data + ")";`), which reaches the sink `directoryContext.search("", search, null)` at `Case08D.java:32`.

## Fix
```java
            String search = "(cn={0})";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, null);
```

## Explanation
The multi-class call chain does nothing to the value - it is the raw request parameter that lands in the concatenated filter, so LDAP metacharacters in `name` are parsed as filter syntax rather than as a search term. A payload like `*)(objectClass=*` terminates the `cn` clause and injects an attacker-chosen one, converting an equality lookup into a match-everything query and disclosing directory entries beyond the intended result. The remediation replaces concatenation with JNDI's parameterized `DirContext.search(String, String, Object[], SearchControls)` overload: `{0}` marks the value position and the untrusted string is passed through `filterArgs`, where the JDK applies RFC 4515 escaping so `*`, `(`, `)`, and backslash become literal characters of the term. The filter's structure is then fixed at compile time and cannot be altered by input; behaviour for legitimate values is unchanged and no additional library is needed. Narrowing the base DN, limiting returned attributes, and using a least-privileged bind account remain worthwhile hardening.
