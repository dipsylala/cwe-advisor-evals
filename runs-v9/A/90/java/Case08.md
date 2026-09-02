## Verdict

Confirmed. `Case08D.handleSink` builds an LDAP search filter by directly concatenating an untrusted string into `"(cn=" + data + ")"` and passes it to `DirContext.search(String, String, SearchControls)`. Any LDAP filter metacharacter in `data` (`*`, `(`, `)`, `\`, NUL) changes the meaning of the filter, letting an attacker widen the match (e.g. `*` to return all entries) or inject additional filter clauses.

## Source

`request.getParameter("name")` in `Case08A.handle` (Case08A.java, line 16). The value is passed unmodified through `Case08B.handleSink` (Case08B.java, line 13) and `Case08C.handleSink` (Case08C.java, line 13) to `Case08D.handleSink`.

## Fix

In `Case08D.java`, replace the manual string concatenation and the 3-argument `search` call with the filter-argument overload that lets JNDI encode the value for you:

```java
String search = "(cn={0})";
SearchControls searchControls = new SearchControls();
NamingEnumeration<SearchResult> answer =
    directoryContext.search("", search, new Object[] { data }, searchControls);
```

Everything else in the method (the try/catch/finally, environment setup, result iteration) stays the same. Only the filter string and the `search(...)` call at lines 29 and 32 change.

## Explanation

`javax.naming.directory.DirContext` provides an overload, `search(Name/String name, String filterExpr, Object[] filterArgs, SearchControls cons)`, where `filterExpr` uses positional placeholders (`{0}`, `{1}`, ...) instead of literal values. Per the JNDI documentation for this method, each element of `filterArgs` is encoded into the filter using the RFC 2254 escaping rules before substitution, so any LDAP special character in the value (`*`, `(`, `)`, `\`, NUL) is escaped rather than interpreted as filter syntax. This mirrors the parameterized-query defense used against SQL injection: the untrusted value is kept structurally separate from the filter grammar instead of being spliced into it as text.

Using this overload removes the need for hand-written escaping logic, which is easy to get wrong (missing a character class, wrong escape prefix, or being bypassed by encoding tricks). It requires no change to the calling servlet or intermediate classes, since `data` is still passed as a plain `String` all the way down the call chain — only the sink itself changes how it uses that value.

If a future change needs multiple substituted values in the same filter, extend the same pattern with additional `{n}` placeholders and matching entries in the `Object[]` array rather than reintroducing string concatenation.
