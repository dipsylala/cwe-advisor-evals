## Verdict

CWE-90 (LDAP Injection) confirmed. The untrusted `data` parameter from the HTTP request flows through Case08A → Case08B → Case08C to Case08D, where it is concatenated directly into an LDAP filter string without escaping and used as the search argument on line 32.

## Source

Line 29-32 in Case08D.java:

```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

The vulnerability exists because LDAP metacharacters in `data` (such as `*`, `(`, `)`, `\`) are not escaped before being inserted into the search filter. An attacker can supply input like `*)(|(cn=*` to alter the filter logic and bypass intended query constraints.

## Fix

Escape LDAP special characters in the user-supplied data before constructing the filter:

```java
private static String escapeLDAP(String input) {
    if (input == null) {
        return null;
    }
    StringBuilder output = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        switch (c) {
            case '*':
                output.append("\\2a");
                break;
            case '(':
                output.append("\\28");
                break;
            case ')':
                output.append("\\29");
                break;
            case '\\':
                output.append("\\5c");
                break;
            case '\0':
                output.append("\\00");
                break;
            default:
                output.append(c);
        }
    }
    return output.toString();
}
```

Then replace line 29 with:

```java
String search = "(cn=" + escapeLDAP(data) + ")";
```

This ensures that LDAP metacharacters are properly escaped according to RFC 4515 before being used in the search filter.

## Explanation

LDAP filter syntax allows certain characters (`*`, `(`, `)`, `\`, NUL) to have special meaning. When untrusted input is concatenated directly into a filter string without escaping, an attacker can inject filter logic to bypass authentication, extract unintended data, or cause denial of service.

The fix escapes each LDAP metacharacter to its hexadecimal representation prefixed with a backslash (e.g., `*` becomes `\2a`). This transforms potentially dangerous input into literal search terms. After escaping, `data` no longer contains unquoted metacharacters, so the filter expression behaves as intended regardless of the user input content.
