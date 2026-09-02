## Verdict
CONFIRMED: LDAP Injection vulnerability. User-controlled input from `request.getParameter("name")` is concatenated directly into an LDAP search filter without sanitization, allowing injection of LDAP metacharacters.

## Source
`Case07A.java` line 16: `data = request.getParameter("name");`

The attacker-controlled `data` parameter flows to `Case07B.handleSink()` where it is used in an LDAP query at line 32.

## Fix
Escape LDAP filter metacharacters before constructing the search filter. Replace lines 29-32 in `Case07B.java`:

```java
String escapedData = escapeLdapFilter(data);
String search = "(cn=" + escapedData + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

Add this helper method to the `Case07B` class:

```java
private static String escapeLdapFilter(String input) {
    if (input == null) {
        return null;
    }
    
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        switch (c) {
            case '*':
                sb.append("\\2a");
                break;
            case '(':
                sb.append("\\28");
                break;
            case ')':
                sb.append("\\29");
                break;
            case '\\':
                sb.append("\\5c");
                break;
            case '\0':
                sb.append("\\00");
                break;
            default:
                sb.append(c);
        }
    }
    return sb.toString();
}
```

## Explanation
LDAP filter syntax uses metacharacters `*`, `(`, `)`, `\`, and NUL to construct queries. An attacker can inject these characters to alter query logic—for example, `*` acts as a wildcard, allowing conditions like `(cn=*)` to match any user, or `(|(cn=admin)(cn=*))` to change OR/AND logic.

The fix escapes all five LDAP metacharacters by replacing each with a backslash followed by its two-digit hexadecimal ASCII value. This is the standard LDAP escaping mechanism defined by RFC 4515. The escaped string is now safe to concatenate into the filter because metacharacters are treated as literal text rather than syntax operators.

The escaped `data` can no longer manipulate the filter structure; all special characters are neutralized before the query reaches the LDAP directory context.
