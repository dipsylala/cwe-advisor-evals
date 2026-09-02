## Verdict
Confirmed. LDAP Injection vulnerability at line 32 via unsanitized concatenation at line 29.

## Source
Case17A passes untrusted input `data` to Case17B.handleSink() at line 18. In a real application, `data` would originate from user input (e.g., HTTP request parameter); in this test case it is hardcoded but treated as untrusted.

## Fix
Replace string concatenation of the LDAP filter with a parameterized search that escapes special characters. Change lines 29-32 from:

```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

To:

```java
String filterTemplate = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterTemplate, new Object[]{data}, null);
```

This uses the parameterized variant of `DirContext.search()` which accepts a filter template and argument array. The framework automatically escapes LDAP metacharacters in `data` (including `*`, `(`, `)`, `\`, and NUL) before substituting into the filter.

## Explanation
LDAP injection occurs when untrusted input is concatenated directly into an LDAP search filter. An attacker can inject LDAP metacharacters to alter query logic. For example, `data = "*)(|(cn=*"` produces the filter `(cn=*)(|(cn=*)` which bypasses authentication or access control logic depending on context.

The parameterized search method separates the filter template from the arguments, allowing the LDAP provider to safely escape special characters before substitution. This is the standard defense mechanism in Java's JNDI/LDAP API and requires no external libraries.
