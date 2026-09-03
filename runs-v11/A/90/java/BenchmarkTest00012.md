## Verdict
CONFIRMED: LDAP Injection vulnerability. The LDAP filter on line 60 concatenates unsanitized user input directly into the filter string, allowing an attacker to inject LDAP filter syntax and manipulate query logic.

## Source
Line 60 constructs an LDAP filter by concatenating `param` (from the request header) without escaping LDAP special characters:
```
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```
The `param` value originates from `request.getHeaders("BenchmarkTest00012")` (line 45) and is URL-decoded but not LDAP-escaped before use.

## Fix
Escape LDAP filter special characters in the `param` variable before concatenating it into the filter string. Add this method to escape LDAP filter input:

```java
private static String escapeLDAPFilter(String input) {
    if (input == null) return "";
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '*': sb.append("\\2a"); break;
            case '(': sb.append("\\28"); break;
            case ')': sb.append("\\29"); break;
            case '\\': sb.append("\\5c"); break;
            case '/': sb.append("\\2f"); break;
            case '\0': sb.append("\\00"); break;
            default: sb.append(c);
        }
    }
    return sb.toString();
}
```

Then escape `param` before using it in the filter:
```java
param = escapeLDAPFilter(param);
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

Alternatively, use a dedicated LDAP filter escaping library such as `com.unboundid:unboundid-ldapsdk`, which provides `LDAPUtil.encodeFilterString(param)`.

## Explanation
LDAP filter metacharacters (`*`, `(`, `)`, `\`, `/`) have special meaning in LDAP filter syntax. When user input is concatenated directly without escaping, an attacker can close the current filter clause and inject arbitrary filter logic—for example, using `*))(&(uid=*` to bypass authentication or retrieve unintended data. Escaping these characters by replacing them with their hex-encoded representations prevents the injection. The code already uses parameterized queries for the street parameter (via `{0}` and the `filters` array); the uid parameter must receive the same treatment through explicit LDAP filter escaping.
