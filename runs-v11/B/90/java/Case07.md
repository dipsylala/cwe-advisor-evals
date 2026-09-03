## Verdict

**Confirmed.** Untrusted user input flows directly from `request.getParameter("name")` to an LDAP filter string constructed via concatenation, enabling LDAP Injection. An attacker can inject LDAP metacharacters (`*`, `(`, `)`) to modify query logic and access unauthorized directory entries.

## Source

- **Origin:** `request.getParameter("name")` in Case07A.java line 16
- **Flow:** Case07A passes data to Case07B.handleSink() (Case07A line 18)
- **Sink:** `directoryContext.search("", search, null)` at Case07B.java line 32, using filter built via concatenation on line 29

## Fix

**Vulnerable code (Case07B.java lines 29, 32):**
```java
String search = "(cn=" + data + ")";
// ...
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
// ...
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data}, new SearchControls());
```

## Explanation

JNDI's `DirContext.search(name, filterExpr, filterArgs, cons)` overload accepts filter arguments separately, escaping each string argument per RFC 4515 (LDAP filter escaping) before interpolating it into the filter template. Replace the concatenated filter string with a parameterized template using `{0}`, `{1}`, etc. as placeholders and pass user input via the `filterArgs` array. Every overload that accepts `filterArgs` requires a trailing `SearchControls` argument; pass `new SearchControls()` for default scope and search behaviour. The platform's own JNDI implementation handles escaping of special characters (`*`, `(`, `)`, `\`, NUL) so they are treated as literal values, not as syntax.

## Behaviour changes

- **Return value:** Unchanged. `DirContext.search()` still returns a `NamingEnumeration<SearchResult>` with the same semantics.
- **Search scope:** Unchanged. `new SearchControls()` applies the default scope (SUBTREE_SCOPE) and search parameters.
- **Error handling:** Unchanged. The call still throws `NamingException` on directory errors.
- **Implicit argument defaults:** The original call passed `null` for `SearchControls`, which JNDI interprets as default controls; the fix explicitly passes `new SearchControls()` to the same effect, making the default explicit and maintainable.
