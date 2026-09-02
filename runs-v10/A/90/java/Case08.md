## Verdict

Confirmed. LDAP Injection vulnerability at line 32.

## Source

User-supplied input is obtained from the HTTP request parameter "name" in Case08A.handle() via `request.getParameter("name")` and flows through the call chain Case08A → Case08B → Case08C → Case08D.

## Fix

In Case08D.handleSink(), escape the user-supplied `data` before using it in the LDAP filter string. Use Spring Security's `org.springframework.ldap.core.LdapUtils.encodeFilterMetaChars()` to sanitize the input:

Replace lines 29-32:
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

With:
```java
String escapedData = org.springframework.ldap.core.LdapUtils.encodeFilterMetaChars(data);
String search = "(cn=" + escapedData + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

This requires adding the Spring LDAP dependency to the project. If Spring is unavailable, implement a custom escaping utility that replaces LDAP filter metacharacters (`*`, `(`, `)`, `\`, and the NUL character) with their RFC 4515 escaped equivalents.

## Explanation

LDAP Injection occurs because the user-controlled `data` parameter is directly concatenated into the LDAP filter string without escaping. An attacker can inject LDAP filter syntax characters like `*` (wildcard), `|` (OR), `&` (AND), `)` (close parenthesis), or `\` (escape) to modify the query logic and bypass authentication or extract unauthorized information.

Escaping these metacharacters prevents the attacker from altering the filter's structure. `LdapUtils.encodeFilterMetaChars()` implements RFC 4515 compliant escaping, converting each special character to its hexadecimal representation prefixed with a backslash (e.g., `*` becomes `\2a`, `(` becomes `\28`). This ensures the input is treated as data, not filter syntax.
