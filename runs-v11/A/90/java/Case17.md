## Verdict
Confirmed. Line 32 performs an LDAP directory search with an unsanitized filter constructed from user-controlled input, enabling filter injection attacks.

## Source
Parameter `data` received at Case17B.handleSink() (line 17) is used to construct an LDAP filter at line 29 without escaping LDAP metacharacters.

## Fix
Replace the string concatenation filter with a parameterized search that properly escapes the input:

```java
// Before (vulnerable):
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);

// After (fixed):
NamingEnumeration<SearchResult> answer = directoryContext.search("", "(cn={0})", new Object[]{data}, null);
```

The corrected code uses `InitialDirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)`, which automatically escapes special characters in the `filterArgs` array when substituting them into the filter expression template using positional placeholders like `{0}`.

## Explanation
LDAP filter syntax uses special metacharacters (`*`, `(`, `)`, `\`, NUL) to control query logic. When user input is directly concatenated into a filter string, an attacker can inject these characters to alter the query. For example, `data = "*)(|(uid=*"` transforms `(cn=*)(|(uid=*)` which changes the logical structure of the filter.

JNDI provides a parameterized search method that safely escapes filter arguments by replacing each positional placeholder with the properly escaped value from the corresponding array element. This prevents injection by encoding special characters so they are treated as literal values rather than filter operators.
