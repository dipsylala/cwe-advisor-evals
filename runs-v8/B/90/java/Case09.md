## Verdict
Exploitable

## Source
The `data` parameter (untrusted, from `HttpServletRequest`) is concatenated directly into the LDAP filter string at line 29.

## Fix
Vulnerable code (line 29-32):
```java
String search = "(cn=" + data + ")";
// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Fixed code:
```java
String search = "(cn={0})";
// Parameterized API with filter argument escaping
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new String[]{data});
```

## Explanation
The vulnerability exists because LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) in the `data` parameter can modify the query structure. An attacker can inject metacharacters to close the current filter term and add logic—for example, `data = "admin*"` produces `(cn=admin*)` (wildcard match), and `data = "*)(objectClass=*"` produces `(cn=*)(objectClass=*)` (changes the filter logic entirely). The fix uses JNDI's parameterized `DirContext.search()` overload with filter arguments. The placeholder `{0}` in the filter string marks where the escaped value will be substituted. The JDK then applies RFC 4515 escaping to each value in the `filterArgs` array, neutralizing metacharacters while preserving the filter structure and semantics.

## Behaviour changes
The third parameter to `DirContext.search()` changes from `null` (no filter arguments) to `new String[]{data}` (filter argument array). This shift is required by the parameterized API and is the mechanism that triggers RFC 4515 escaping within JNDI. The search scope, base DN, and return attributes remain unchanged; only the filter argument handling differs. No behavioral regressions: the query still searches the same scope with the same logical intent, but user input is now safely escaped.
