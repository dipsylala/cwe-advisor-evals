## Verdict
CONFIRMED

## Source
Line 56 constructs an LDAP filter using unescaped user input:
```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
```

The `param` variable originates from `request.getParameterValues("BenchmarkTest00044")` at line 44 without sanitization. This filter is then passed to `ctx.search()` at line 60, where an attacker can inject LDAP metacharacters to modify the query structure.

## Fix
Escape special LDAP filter characters in the user input before constructing the filter. Replace line 56 with:

```java
String escapedParam = escapeLDAPFilter(param);
String filter = "(&(objectclass=person)(uid=" + escapedParam + "))";
```

Add a helper method to escape LDAP filter special characters:

```java
private static String escapeLDAPFilter(String input) {
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

## Explanation
LDAP filter syntax uses metacharacters like `*`, `(`, `)`, `\`, and `/` for query operators. When user input is directly concatenated into a filter string without escaping, attackers can inject these characters to bypass authentication checks or extract unauthorized data.

For example, an attacker could submit `uid=*))(&(uid=*` to transform the filter from `(&(objectclass=person)(uid=*))(&(uid=*` which would match any user.

The fix escapes each special character using its hex representation (e.g., `*` becomes `\2a`), preventing injection attacks while preserving the legitimate filter structure. This approach follows RFC 4515 LDAP filter escaping rules and is compatible with Java's JNDI/LDAP implementation.
