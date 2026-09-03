## Verdict
Confirmed: LDAP Injection via unsanitized filter parameter

## Source
Line 29 constructs an LDAP search filter by concatenating user-controlled `data` directly:
```
String search = "(cn=" + data + ")";
```
The `data` parameter originates from the HTTP request (line 17, `handleSink()` signature), passes through the call chain without validation, and reaches the LDAP filter at line 32.

An attacker can inject LDAP metacharacters (e.g., `*`, `(`, `)`, `\`) to alter the query logic.

## Fix
Escape special LDAP characters in the filter value before concatenation. Implement LDAP filter escaping by replacing LDAP metacharacters with their hex-encoded equivalents:

```java
private static String escapeLdapFilterValue(String input) {
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
            case '/':
                sb.append("\\2f");
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

Then apply escaping to the user input:
```java
String search = "(cn=" + escapeLdapFilterValue(data) + ")";
```

## Explanation
LDAP filters use metacharacters to construct queries. Unescaped user input allows filter injection: `data = "admin*"` produces `(cn=admin*)` (wildcard match), while `data = "*)(|(cn=*"` breaks the filter into `(cn=*)(|(cn=*))` (logical OR).

The fix prevents injection by escaping these characters with RFC 4515–compliant hex encoding, so all user input is treated as literal filter values. The escaping function replaces the five LDAP metacharacters (`*`, `(`, `)`, `\`, `/`) and NUL with their backslash-hex representations, which the LDAP parser interprets as literal characters rather than syntax operators.

Alternative: use a parameterized query API if available (Spring LDAP's `LdapQueryBuilder` or similar), though javax.naming.directory lacks a built-in parameterized API.
