## Verdict
exploitable

## Source
`Case07A.java` line 16: `data = request.getParameter("name")` reads the attacker-controlled HTTP request parameter `name`. The value is passed unvalidated and unencoded to `(new Case07B()).handleSink(data, request, response)` at line 18. In `Case07B.java` line 29 it is concatenated into an LDAP search filter, `String search = "(cn=" + data + ")"`, and the filter reaches the sink `directoryContext.search("", search, null)` at line 32. No sanitisation, escaping, or allowlist check occurs anywhere on the path.

## Fix
```java
            // Case07B.java - use a parameterised filter expression so JNDI escapes the value
            String search = "(cn={0})";

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, searchControls);
```

## Explanation
The request parameter flows directly into a string-concatenated LDAP filter, so an attacker can inject filter metacharacters such as `*`, `)`, `(`, `&`, and `|` to break out of the `cn` comparison and rewrite the query - for example `*)(|(objectClass=*)` turns a targeted lookup into a full directory enumeration, and similar constructs enable filter-based blind extraction of attribute values that are then echoed back through `IO.writeLine`. The fix replaces concatenation with the JNDI parameterised overload `DirContext.search(String, String, Object[], SearchControls)`, where `{0}` is a placeholder that the provider encodes according to RFC 4515 before it becomes part of the filter, so the input can only ever be interpreted as a literal assertion value rather than filter syntax. An explicit `SearchControls` instance is supplied because the parameterised overload takes controls rather than relying on the previous `null`, and the search scope is set explicitly to preserve intended behaviour. If the application only ever expects a constrained identifier, adding an allowlist validation of `data` before the search gives useful defence in depth, but the parameterised filter is the primary control.
