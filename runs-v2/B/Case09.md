## Verdict
exploitable

## Source
Untrusted data enters at `Case09A.java:16` - `data = request.getParameter("name")`, an attacker-controlled HTTP request parameter read in the public servlet entry point `Case09A.handle()` (`Case09A extends AbstractTestCaseServlet`). It travels unmodified through four pass-through hops: `Case09A.java:18` to `Case09B.handleSink`, `Case09B.java:12` to `Case09C.handleSink`, `Case09C.java:12` to `Case09D.handleSink`, and `Case09D.java:12` to `Case09E.handleSink`. None of the intermediate methods validate, encode, or constrain the value. In `Case09E.handleSink` it is concatenated into an LDAP search filter at `Case09E.java:29` (`String search = "(cn=" + data + ")";`), and that filter reaches the sink `directoryContext.search("", search, null)` at `Case09E.java:32`.

## Fix
```java
            String search = "(cn={0})";

            // SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, null);
```

## Explanation
Length of the call chain does not break the taint path - every hop simply forwards the parameter, so the raw request value is what gets pasted into the filter string. Because an LDAP filter is parsed as an expression tree, injected metacharacters change the query itself: a payload such as `*)(objectClass=*` closes the `cn` term and opens an attacker-controlled clause, turning a targeted lookup into a match-everything search that discloses directory entries the request should not reach. The fix moves the value out of the filter text and into JNDI's parameterized `DirContext.search(String, String, Object[], SearchControls)` overload, using `{0}` as a placeholder and passing the untrusted string via `filterArgs`; the JDK escapes it per RFC 4515 so `*`, `(`, `)`, and backslash are matched literally. The filter structure becomes fixed and input-independent, legitimate lookups behave identically, and no new dependency is introduced. A narrow base DN, restricted returned attributes, and a least-privileged bind account are sensible additional controls.
