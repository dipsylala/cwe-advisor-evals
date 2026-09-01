## Verdict

Exploitable. Untrusted HTTP parameter flows directly into LDAP filter via string concatenation, allowing injection of LDAP metacharacters.

## Source

`request.getParameter("name")` in Case07A (line 16); passed to Case07B.handleSink() where it is concatenated into the filter string without escaping.

## Fix

**Vulnerable Code (Case07B, lines 29-32):**

```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed Code:**

```java
String search = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data});
```

## Explanation

The fix uses JNDI's parameterized search filter API instead of string concatenation. The `{0}` placeholder marks where the user-supplied value belongs in the filter structure, and the `filterArgs` parameter (a String array) passes the actual data separately. JNDI's DirContext implementation automatically escapes filter arguments according to RFC 4515, neutralizing LDAP metacharacters (`*`, `(`, `)`, backslash, NUL). The attacker's input is now treated as a literal value, not as filter syntax, preventing injection attacks.

## Behaviour changes

None. The parameterized API produces identical search results to the original vulnerable code; it differs only in safety. All parameters, return types, and error handling remain the same.
