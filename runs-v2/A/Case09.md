## Verdict
exploitable

## Source
`Case09A.java` line 16: `data = request.getParameter("name")` reads the attacker-controlled HTTP request parameter `name`. It is relayed unchanged through `Case09B.handleSink` (line 13), `Case09C.handleSink` (line 13), and `Case09D.handleSink` (line 13) into `Case09E.handleSink`. In `Case09E.java` line 29 the value is concatenated into an LDAP search filter, `String search = "(cn=" + data + ")"`, which is then passed to the sink `directoryContext.search("", search, null)` at line 32. No layer in the chain validates or encodes the value.

## Fix
```java
            // Case09E.java - use a parameterised filter expression so JNDI escapes the value
            String search = "(cn={0})";

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, searchControls);
```

## Explanation
Each of the four intermediate methods simply forwards its `data` argument to the next class, so the untrusted request parameter arrives at `Case09E` completely unmodified and the depth of the chain has no bearing on exploitability. Building the filter by concatenation lets an attacker inject LDAP filter metacharacters - `*`, `(`, `)`, `&`, `|`, and `\` - to terminate the `cn` assertion early and append their own clauses, for instance turning the lookup into a wildcard match over every entry or into a boolean oracle that leaks attribute values one character at a time through the results printed by `IO.writeLine`. The fix uses the JNDI parameterised search overload `DirContext.search(String, String, Object[], SearchControls)`, in which the `{0}` placeholder is filled by the provider with an RFC 4515-escaped rendering of the supplied argument, so the input can only be interpreted as data inside the assertion and never as filter structure. The overload requires a `SearchControls` argument, so one is created explicitly with the scope set rather than relying on the previous `null`. Constraining `data` to an expected identifier pattern at the servlet entry point in `Case09A` remains a useful additional check.
