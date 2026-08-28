## Verdict
exploitable

## Source
`Case08A.java` line 16: `data = request.getParameter("name")` reads the attacker-controlled HTTP request parameter `name`. It is forwarded unchanged through `Case08B.handleSink` (line 13) and `Case08C.handleSink` (line 13) to `Case08D.handleSink`. In `Case08D.java` line 29 the value is concatenated into an LDAP search filter, `String search = "(cn=" + data + ")"`, which reaches the sink `directoryContext.search("", search, null)` at line 32. None of the three intermediate hops validates, escapes, or reassigns the value.

## Fix
```java
            // Case08D.java - use a parameterised filter expression so JNDI escapes the value
            String search = "(cn={0})";

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> answer =
                directoryContext.search("", search, new Object[] { data }, searchControls);
```

## Explanation
The multi-class call chain is pure pass-through delegation, so the taint from `request.getParameter` survives intact to the filter construction in `Case08D`; the extra hops change nothing about exploitability. Because the value is concatenated into the filter string, an attacker can supply LDAP filter metacharacters such as `*)(|(objectClass=*` to escape the `cn` assertion and rewrite the query into an arbitrary one, enumerating directory entries or performing blind character-by-character extraction of attributes that are then written back out by `IO.writeLine`. The remediation replaces the concatenation with the JNDI parameterised overload `DirContext.search(String, String, Object[], SearchControls)`; the `{0}` placeholder is substituted by the provider with an RFC 4515-encoded form of the argument, so injected metacharacters are treated as literal characters of the assertion value rather than filter syntax. A `SearchControls` instance is now passed explicitly since that overload requires it, with the scope set to preserve the original search behaviour. Validating `data` against an expected identifier format in `Case08A` before it enters the chain is a worthwhile secondary control.
