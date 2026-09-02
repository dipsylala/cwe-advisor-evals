## Verdict

Exploitable. CWE-90 (LDAP Injection), confidence: high.

- Location: `Case07B.java`, line 32 (sink), filter built at line 29.
- Source: `request.getParameter("name")` in `Case07A.java` line 16, stored in local `data`.
- Sink: `directoryContext.search("", search, null)` in `Case07B.java` line 32, where `search` is built by string concatenation at line 29: `"(cn=" + data + ")"`.

## Source

`Case07A.handle(HttpServletRequest, HttpServletResponse)` reads the untrusted parameter and forwards it unmodified:

```java
data = request.getParameter("name");
(new Case07B()).handleSink(data, request, response);
```

`Case07B.handleSink` concatenates `data` directly into an LDAP filter string with no escaping or validation, then passes that string to `DirContext.search`. No sanitization, allowlisting, or encoding occurs anywhere along the path, so an attacker-controlled `name` parameter reaches the LDAP filter parser unmodified. A value such as `*)(uid=*` closes the `cn` clause and appends an always-true clause, letting an attacker widen or hijack the search.

## Fix

Vulnerable code (`Case07B.java`, lines 29-32):

```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed code:

```java
String search = "(cn={0})";

// Filter value is passed via filterArgs; JNDI escapes it per RFC 4515 before the query is sent.
NamingEnumeration<SearchResult> answer =
    directoryContext.search("", search, new Object[]{ data }, new SearchControls());
```

This also requires adding the import already available in this file's package (`javax.naming.directory.*` is already imported, which covers `SearchControls`).

## Explanation

The vulnerable code builds the LDAP filter by string concatenation, so any LDAP metacharacter (`*`, `(`, `)`, backslash) in `data` is interpreted as filter syntax rather than as literal search data, letting an attacker close the `cn=` clause and inject additional filter terms. The fix replaces concatenation with JNDI's parameterized search: the filter template `"(cn={0})"` keeps the query structure fixed, and `data` is supplied separately through the `filterArgs` array. Per the `DirContext.search` Javadoc, a `String`-valued filter argument is escaped per RFC 4515 by the provider before substitution, which neutralizes `*`, `(`, `)`, and backslash in the value without altering legitimate characters such as `/`. This is the primary defence named in the Java-specific guidance (`cwe/90/java/INDEX.md`) and closes the injection point at the sink identified in Step 4.

## Behaviour changes

- Replaced `null` as the third (now fourth) argument with an explicit `new SearchControls()`. Per the JNDI Javadoc, passing `null` for `SearchControls` is equivalent to using a default-constructed `SearchControls()`, so this is not a functional change - it is required because the 4-argument overload with `filterArgs` has no null-controls shorthand.
- No other behavioural change: the filter still matches on `cn` equal to the supplied value, the search base (`""`), return-all-attributes default, and exception/finally handling are all unchanged.
