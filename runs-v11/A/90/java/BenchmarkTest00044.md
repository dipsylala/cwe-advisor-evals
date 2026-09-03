## Verdict
Confirmed LDAP Injection vulnerability. User-controlled input is directly concatenated into an LDAP filter without escaping, allowing filter manipulation.

## Source
Line 56: The LDAP filter is constructed by concatenating the request parameter `param` directly into the filter string without any escaping.

```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
```

This unsanitized filter is then passed to `ctx.search()` on line 60, making it a taint sink.

## Fix
Escape the user input using LDAP filter character encoding before concatenating it into the filter. Replace line 56 with:

```java
String escapedParam = escapeLDAPFilter(param);
String filter = "(&(objectclass=person)(uid=" + escapedParam + "))";
```

Add the following static helper method to the class:

```java
private static String escapeLDAPFilter(String input) {
    if (input == null) {
        return "";
    }
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
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

Alternatively, use Apache Directory API's built-in escaping if available in your dependencies: `org.apache.directory.ldap.client.api.LdapClientUtils.escapeFilterValue()` or an equivalent library function.

## Explanation
LDAP injection occurs when untrusted input is embedded into LDAP filter syntax without proper escaping. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`) to modify the query logic and bypass authentication or extract unauthorized data.

The fix escapes these five special characters by encoding them as their octal equivalents (`\2a`, `\28`, `\29`, `\5c`, `\00`), preventing them from being interpreted as LDAP syntax. This ensures the entire input is treated as literal data rather than filter operators, eliminating the injection vector while preserving the intended search functionality.
