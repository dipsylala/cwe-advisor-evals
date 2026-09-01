## Verdict

Real issue. The LDAP filter on line 56 concatenates unsanitized user input into the filter string before passing it to `ctx.search()` at line 60, allowing an attacker to inject LDAP filter metacharacters.

## Source

Line 56 constructs the filter by concatenating `param` directly:
```
String filter = "(&(objectclass=person)(uid=" + param + "))";
```

The `param` variable originates from the HTTP request parameter `BenchmarkTest00044` (lines 44-47) and flows unescaped into the filter string passed to `ctx.search()` (line 60).

## Fix

Escape the user input using RFC 4515 compliant LDAP filter escaping before concatenating it into the filter:

```java
String param = values[0];
String escapedParam = escapeLDAPFilterValue(param);
String filter = "(&(objectclass=person)(uid=" + escapedParam + "))";
```

Where `escapeLDAPFilterValue` escapes the characters that have special meaning in LDAP filters:

```java
private static String escapeLDAPFilterValue(String value) {
    StringBuilder sb = new StringBuilder();
    for (char c : value.toCharArray()) {
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

Alternatively, if using Spring Security, use `org.springframework.ldap.core.LdapEncoder.filterEncode()` or if using Unboundid LDAP SDK, use `com.unboundid.ldap.sdk.filter.Filter.encodeFilterValue()`.

## Explanation

LDAP injection occurs when untrusted input is concatenated into LDAP filter syntax without escaping. An attacker can inject filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter query logic—for example, using `*))(&(uid=*` to match any user, or manipulating boolean operators to bypass authorization checks.

The fix escapes all special characters in the user-controlled value by replacing them with their hexadecimal escape sequences per RFC 4515, preventing the attacker's input from being interpreted as filter syntax. The input is then safely concatenated as literal filter text.
