## Verdict

Confirmed. Line 32 is vulnerable to LDAP Injection via the concatenated filter string at line 29.

## Source

The `data` parameter (line 17) flows directly into the LDAP filter without escaping. At line 29, it is concatenated into the filter string `"(cn=" + data + ")"`, and at line 32 this untrusted filter is passed to `directoryContext.search()` unencoded.

An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify query logic. For example, `data = "*` closes the equality clause and turns the filter into a presence match that returns all entries.

## Fix

Replace lines 29-32:

```java
String search = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data});
```

Use `{0}` as a placeholder in the filter string and pass the untrusted data via the `filterArgs` parameter. JNDI automatically escapes string-valued arguments according to RFC 4515 before the filter is parsed.

## Explanation

JNDI's parameterized `DirContext.search(String, String, Object[])` overload separates filter structure from user data. The placeholder `{0}` marks where the argument substitution occurs, and JNDI escapes the value supplied in the `filterArgs` array (here, `new String[]{data}`) before substituting it into the filter. This escaping encodes the special characters `*`, `(`, `)`, `\`, and NUL so they are treated as literal characters rather than filter syntax. The fix preserves the search semantics—the query still searches for entries with `cn` equal to the supplied value—while closing the injection point.

## Behaviour changes

The query now correctly searches for a common name matching the exact value in `data`, with LDAP filter metacharacters neutralized. Any injection probe (e.g., `data = "*`) now searches for that literal string rather than modifying query logic. No other behavior changes—the search scope, result handling, and exception logic remain unchanged.
