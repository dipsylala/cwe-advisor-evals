## Verdict

True Positive. LDAP filter injection is present. The `param` value, derived from a request header and URL-decoded at line 52, is concatenated directly into an LDAP filter at line 60 without sanitization. This allows an attacker to inject LDAP metacharacters and alter the filter logic.

## Source

Line 60:
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

The `param` value originates from the request header at line 45, is URL-decoded at line 52, and flows directly into the LDAP filter string construction without any escaping or validation.

## Fix

Escape LDAP filter special characters in the `param` value before constructing the filter. Add an escaping helper method and apply it when building the filter:

```java
private static String escapeLDAPFilter(String input) {
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

Then at line 60, apply the escaping:

```java
String filter = "(&(objectclass=person))(|(uid=" + escapeLDAPFilter(param) + ")(street={0}))";
```

## Explanation

LDAP injection occurs when untrusted user input is concatenated into LDAP filter strings without escaping. LDAP filters use special characters like `*` (wildcard), `(` and `)` (grouping), `&` (AND), and `|` (OR) to alter filter logic. An attacker can inject these characters to bypass authentication or retrieve unintended records.

The fix applies character-level escaping to encode LDAP special characters as hex escape sequences (`\XX`). This prevents the metacharacters from being interpreted as filter operators. The escaped input becomes literal search criteria rather than filter syntax, neutralizing the injection attack while preserving the intended search functionality.
