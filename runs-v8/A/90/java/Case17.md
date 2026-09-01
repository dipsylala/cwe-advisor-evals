## Verdict
Confirmed LDAP Injection in `Case17B.java` at line 32. The `data` parameter is concatenated directly into an LDAP filter string without escaping, allowing attackers to inject LDAP metacharacters and manipulate the search query logic.

## Source
Line 29–32 in `Case17B.java`:
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

The variable `data` originates from the `handleSink()` method parameter (line 17), which receives user-controlled input from `Case17A.handle()`.

## Fix
Escape all LDAP filter metacharacters in the `data` variable before constructing the search filter. Replace line 29 with a call to an LDAP escape utility:

```java
String search = "(cn=" + escapeLdapFilter(data) + ")";
```

Implement the escape method:

```java
private static String escapeLdapFilter(String input) {
    if (input == null) {
        return null;
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

Alternatively, use Apache Directory API's built-in escaping via `org.apache.directory.ldap.client.api.LdapConnectionConfig` or `org.apache.commons.lang3.StringUtils` with a custom escape function.

## Explanation
LDAP metacharacters carry special meaning in filter syntax. The characters `*`, `(`, `)`, `\`, `/`, and NUL allow an attacker to:
- Use `*` as a wildcard to match any substring
- Break out of the current filter clause with `)`
- Create new clauses with `(`
- Use boolean operators like `|(cn=*))` to bypass authentication or search constraints

Escaping replaces these characters with their hexadecimal escape sequences (e.g., `*` becomes `\2a`), ensuring they are treated as literal characters within the filter value, not as operators. This is the standard LDAP injection defense and applies to all user-controlled data concatenated into filter strings.
